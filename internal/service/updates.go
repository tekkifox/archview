package service

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"html/template"
	"io"
	"log"
	"net/http"
	"net/url"
	"os"
	"regexp"
	"strconv"
	"strings"
	"time"
	"unicode"
)

const (
	defaultUpdateSchedule = "04:30"
	defaultUpdateLabel    = "archview.update=auto"
	defaultUpdateHistory  = 20

	updateResultUpToDate    = "up-to-date"
	updateResultUpdated     = "updated"
	updateResultWouldUpdate = "would-update"
	updateResultFailed      = "failed: "
)

// AutoUpdateConfig controls the opt-in, label-scoped container updater. Every
// field is off or safe by default: an ArchView with no ARCHVIEW_UPDATE_*
// environment variables never schedules a run.
type AutoUpdateConfig struct {
	Enabled      bool
	Schedule     string
	Label        string
	DryRun       bool
	Exclude      []string
	HistoryLimit int
}

// UpdateExcluded names a running container that carries the opt-in label but
// was deliberately skipped, together with the reason it was skipped.
type UpdateExcluded struct {
	Name   string `json:"name"`
	Reason string `json:"reason"`
}

// UpdateSelection is the current label-scoped selection. OptedIn contains the
// containers a run would consider; Excluded contains label-carrying containers
// that the built-in or configured exclusions skip.
type UpdateSelection struct {
	OptedIn  []string         `json:"optedIn"`
	Excluded []UpdateExcluded `json:"excluded"`
}

// UpdateContainerResult records one container's outcome in a run.
type UpdateContainerResult struct {
	Name      string `json:"name"`
	OldDigest string `json:"oldDigest"`
	NewDigest string `json:"newDigest"`
	Result    string `json:"result"`
}

// UpdateRun is one complete pass of the updater. Only the most recent
// HistoryLimit runs are retained in memory.
type UpdateRun struct {
	StartedAt  time.Time               `json:"startedAt"`
	FinishedAt time.Time               `json:"finishedAt"`
	Trigger    string                  `json:"trigger"`
	DryRun     bool                    `json:"dryRun"`
	Error      string                  `json:"error,omitempty"`
	Containers []UpdateContainerResult `json:"containers"`
}

// UpdatesResponse is the payload of GET /api/updates.
type UpdatesResponse struct {
	Enabled        bool            `json:"enabled"`
	DryRun         bool            `json:"dryRun"`
	Schedule       string          `json:"schedule"`
	Label          string          `json:"label"`
	NextRun        *time.Time      `json:"nextRun"`
	Running        bool            `json:"running"`
	Selection      UpdateSelection `json:"selection"`
	SelectionError string          `json:"selectionError,omitempty"`
	Runs           []UpdateRun     `json:"runs"`
}

type updateSchedule struct {
	hour   int
	minute int
}

var dailySchedulePattern = regexp.MustCompile(`^([01]?[0-9]|2[0-3]):([0-5][0-9])$`)

func parseUpdateSchedule(raw string) (updateSchedule, error) {
	value := strings.TrimSpace(raw)
	match := dailySchedulePattern.FindStringSubmatch(value)
	if match == nil {
		return updateSchedule{}, fmt.Errorf("invalid daily time %q: want HH:MM", value)
	}
	hour, _ := strconv.Atoi(match[1])
	minute, _ := strconv.Atoi(match[2])
	return updateSchedule{hour: hour, minute: minute}, nil
}

func parseUpdateLabel(raw string) (key, value string, err error) {
	key, value, _ = strings.Cut(strings.TrimSpace(raw), "=")
	key = strings.TrimSpace(key)
	value = strings.TrimSpace(value)
	if key == "" {
		return "", "", errors.New("label must be key=value")
	}
	return key, value, nil
}

func normalizeAutoUpdateConfig(cfg AutoUpdateConfig) (AutoUpdateConfig, error) {
	if strings.TrimSpace(cfg.Schedule) == "" {
		cfg.Schedule = defaultUpdateSchedule
	}
	if _, err := parseUpdateSchedule(cfg.Schedule); err != nil {
		return cfg, fmt.Errorf("ARCHVIEW_UPDATE_SCHEDULE: %w", err)
	}
	if strings.TrimSpace(cfg.Label) == "" {
		cfg.Label = defaultUpdateLabel
	}
	if _, _, err := parseUpdateLabel(cfg.Label); err != nil {
		return cfg, fmt.Errorf("ARCHVIEW_UPDATE_LABEL: %w", err)
	}
	if cfg.HistoryLimit <= 0 {
		cfg.HistoryLimit = defaultUpdateHistory
	}
	seen := make(map[string]struct{}, len(cfg.Exclude))
	excluded := make([]string, 0, len(cfg.Exclude))
	for _, name := range cfg.Exclude {
		name = strings.TrimSpace(name)
		if name == "" {
			continue
		}
		if _, ok := seen[name]; ok {
			continue
		}
		seen[name] = struct{}{}
		excluded = append(excluded, name)
	}
	cfg.Exclude = excluded
	return cfg, nil
}

func nextUpdateRun(now time.Time, schedule string) time.Time {
	parsed, err := parseUpdateSchedule(schedule)
	if err != nil {
		parsed, _ = parseUpdateSchedule(defaultUpdateSchedule)
	}
	location := now.Location()
	next := time.Date(now.Year(), now.Month(), now.Day(), parsed.hour, parsed.minute, 0, 0, location)
	if !next.After(now) {
		next = next.AddDate(0, 0, 1)
	}
	return next
}

// updateContainer is the subset of a Docker container listing that selection
// needs. It is separate from dockerContainer so tests can build one directly.
type updateContainer struct {
	ID      string
	Name    string
	Image   string
	ImageID string
	Labels  map[string]string
}

func containerUpdateCandidate(container dockerContainer) updateContainer {
	return updateContainer{
		ID:      container.ID,
		Name:    cleanDockerName(container.Names),
		Image:   container.Image,
		ImageID: container.ImageID,
		Labels:  container.Labels,
	}
}

// selectUpdateContainers applies the label opt-in and every exclusion. A
// container without the label is not part of the selection at all, so it
// appears in neither list.
func selectUpdateContainers(containers []dockerContainer, cfg AutoUpdateConfig, selfHostname string) ([]updateContainer, []UpdateExcluded) {
	key, value, err := parseUpdateLabel(cfg.Label)
	if err != nil {
		return nil, nil
	}

	selected := make([]updateContainer, 0, len(containers))
	excluded := make([]UpdateExcluded, 0)
	for _, raw := range containers {
		container := containerUpdateCandidate(raw)
		labelValue, ok := container.Labels[key]
		if !ok {
			continue
		}
		if value != "" && labelValue != value {
			continue
		}
		if reason := updateExclusionReason(container, cfg.Exclude, selfHostname); reason != "" {
			excluded = append(excluded, UpdateExcluded{Name: container.Name, Reason: reason})
			continue
		}
		selected = append(selected, container)
	}
	return selected, excluded
}

func updateExclusionReason(container updateContainer, configured []string, selfHostname string) string {
	name := strings.TrimPrefix(strings.TrimSpace(container.Name), "/")
	lower := strings.ToLower(name)

	if nameHasToken(lower, "archview") || sameContainerID(container.ID, selfHostname) {
		return "archview"
	}
	if strings.Contains(lower, "socket-proxy") || strings.Contains(lower, "socketproxy") {
		return "socket proxy"
	}
	if nameHasToken(lower, "watchtower") {
		return "watchtower"
	}
	for _, excluded := range configured {
		if strings.TrimSpace(excluded) == name {
			return "configured exclusion"
		}
	}
	return ""
}

func nameHasToken(name, token string) bool {
	for _, part := range strings.FieldsFunc(name, func(r rune) bool {
		return !unicode.IsLetter(r) && !unicode.IsDigit(r)
	}) {
		if strings.EqualFold(part, token) {
			return true
		}
	}
	return false
}

func sameContainerID(id, hostname string) bool {
	id = strings.TrimPrefix(strings.TrimSpace(id), "sha256:")
	hostname = strings.TrimPrefix(strings.TrimSpace(hostname), "sha256:")
	if len(id) < 12 || len(hostname) < 12 {
		return false
	}
	if !isHexIdent(id) || !isHexIdent(hostname) {
		return false
	}
	return strings.HasPrefix(id, hostname) || strings.HasPrefix(hostname, id)
}

func isHexIdent(value string) bool {
	for _, char := range value {
		switch {
		case char >= '0' && char <= '9':
		case char >= 'a' && char <= 'f':
		case char >= 'A' && char <= 'F':
		default:
			return false
		}
	}
	return true
}

func updateSelfHostname() string {
	hostname, err := os.Hostname()
	if err != nil {
		return ""
	}
	return strings.TrimSpace(hostname)
}

type imageReference struct {
	Original   string
	Repository string
	Tag        string
	Digest     string
}

var imageIDReferencePattern = regexp.MustCompile(`^(sha256:)?[0-9a-fA-F]{64}$`)

func parseImageReference(raw string) (imageReference, error) {
	original := strings.TrimSpace(raw)
	if original == "" {
		return imageReference{}, errors.New("container has no image reference")
	}
	if imageIDReferencePattern.MatchString(original) {
		return imageReference{}, fmt.Errorf("image reference %q is an image ID, not a registry tag", original)
	}

	reference := imageReference{Original: original}
	if at := strings.Index(original, "@"); at >= 0 {
		reference.Repository = strings.TrimSpace(original[:at])
		reference.Digest = strings.TrimSpace(original[at+1:])
	} else {
		reference.Repository = original
		if colon := strings.LastIndex(original, ":"); colon > strings.LastIndex(original, "/") {
			reference.Repository = strings.TrimSpace(original[:colon])
			reference.Tag = strings.TrimSpace(original[colon+1:])
		}
	}
	if reference.Repository == "" {
		return imageReference{}, fmt.Errorf("image reference %q has no repository", original)
	}
	if reference.Digest == "" && reference.Tag == "" {
		reference.Tag = "latest"
	}
	return reference, nil
}

func canonicalRepository(repository string) string {
	value := strings.ToLower(strings.TrimSpace(repository))
	value = strings.TrimPrefix(value, "https://")
	value = strings.TrimPrefix(value, "http://")
	value = strings.TrimSuffix(value, "/")
	for _, prefix := range []string{"index.docker.io/", "registry-1.docker.io/", "docker.io/"} {
		value = strings.TrimPrefix(value, prefix)
	}
	value = strings.TrimPrefix(value, "library/")
	return value
}

func repositoriesEqual(left, right string) bool {
	return canonicalRepository(left) == canonicalRepository(right)
}

// imageRepoDigest returns the digest for repository from an image's
// RepoDigests. When no repository matches, the first digest is used: it is
// still a stable content identifier for the local image.
func imageRepoDigest(repoDigests []string, repository string) string {
	for _, entry := range repoDigests {
		at := strings.Index(entry, "@")
		if at < 0 {
			continue
		}
		if repositoriesEqual(entry[:at], repository) {
			return strings.TrimSpace(entry[at+1:])
		}
	}
	for _, entry := range repoDigests {
		if at := strings.Index(entry, "@"); at >= 0 {
			return strings.TrimSpace(entry[at+1:])
		}
	}
	return ""
}

// decideImageChanged treats an unchanged image ID as up to date even when a
// digest is missing, then falls back to digest comparison and finally to image
// IDs. That keeps registries that omit RepoDigests from causing a recreation.
func decideImageChanged(oldDigest, newDigest, oldID, newID string) bool {
	if oldID != "" && newID != "" && oldID == newID {
		return false
	}
	if oldDigest != "" && newDigest != "" {
		return oldDigest != newDigest
	}
	return oldID != newID
}

type dockerImageInspect struct {
	ID          string   `json:"Id"`
	RepoDigests []string `json:"RepoDigests"`
}

type dockerContainerInspectFull struct {
	ID              string         `json:"Id"`
	Name            string         `json:"Name"`
	Image           string         `json:"Image"`
	Config          map[string]any `json:"Config"`
	HostConfig      map[string]any `json:"HostConfig"`
	NetworkSettings struct {
		Networks map[string]map[string]any `json:"Networks"`
	} `json:"NetworkSettings"`
}

func (s *Server) listRunningContainers(ctx context.Context) ([]dockerContainer, error) {
	var containers []dockerContainer
	if _, err := s.dockerRequest(ctx, http.MethodGet, "/containers/json?all=0", nil, &containers); err != nil {
		return nil, err
	}
	return containers, nil
}

func (s *Server) inspectContainer(ctx context.Context, id string) (dockerContainerInspectFull, error) {
	var inspect dockerContainerInspectFull
	_, err := s.dockerRequest(ctx, http.MethodGet, "/containers/"+url.PathEscape(id)+"/json", nil, &inspect)
	return inspect, err
}

func (s *Server) inspectImage(ctx context.Context, reference string) (dockerImageInspect, error) {
	var image dockerImageInspect
	// Docker image references contain slashes; the Engine API expects them
	// literally in the path (matching the official Docker client), not
	// percent-encoded.
	_, err := s.dockerRequest(ctx, http.MethodGet, "/images/"+reference+"/json", nil, &image)
	return image, err
}

func (s *Server) currentUpdateSelection(ctx context.Context) (UpdateSelection, error) {
	selection := UpdateSelection{
		OptedIn:  []string{},
		Excluded: []UpdateExcluded{},
	}

	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	containers, err := s.listRunningContainers(ctx)
	if err != nil {
		return selection, err
	}
	selected, excluded := selectUpdateContainers(containers, s.cfg.AutoUpdate, updateSelfHostname())
	for _, container := range selected {
		selection.OptedIn = append(selection.OptedIn, container.Name)
	}
	selection.Excluded = append(selection.Excluded, excluded...)
	return selection, nil
}

func (s *Server) updateStatus(ctx context.Context, includeSelection bool) UpdatesResponse {
	cfg := s.cfg.AutoUpdate
	response := UpdatesResponse{
		Enabled:   cfg.Enabled,
		DryRun:    cfg.DryRun,
		Schedule:  cfg.Schedule,
		Label:     cfg.Label,
		Selection: UpdateSelection{OptedIn: []string{}, Excluded: []UpdateExcluded{}},
	}
	if cfg.Enabled {
		next := nextUpdateRun(time.Now(), cfg.Schedule)
		response.NextRun = &next
	}

	runs, running := s.updateSnapshot()
	response.Runs = runs
	response.Running = running

	if includeSelection {
		selection, err := s.currentUpdateSelection(ctx)
		if err != nil {
			response.SelectionError = err.Error()
		} else {
			response.Selection = selection
		}
	}
	return response
}

func (s *Server) updateSnapshot() ([]UpdateRun, bool) {
	s.updateStateMu.RLock()
	defer s.updateStateMu.RUnlock()
	runs := append([]UpdateRun(nil), s.updateRuns...)
	if runs == nil {
		runs = []UpdateRun{}
	}
	return runs, s.updateRunning
}

func (s *Server) setUpdateRunning(running bool) {
	s.updateStateMu.Lock()
	s.updateRunning = running
	s.updateStateMu.Unlock()
}

func (s *Server) recordUpdateRun(run UpdateRun) {
	s.updateStateMu.Lock()
	defer s.updateStateMu.Unlock()
	limit := s.cfg.AutoUpdate.HistoryLimit
	if limit <= 0 {
		limit = defaultUpdateHistory
	}
	s.updateRuns = append([]UpdateRun{run}, s.updateRuns...)
	if len(s.updateRuns) > limit {
		s.updateRuns = s.updateRuns[:limit]
	}
}

// RunAutoUpdateScheduler wakes once per day at ARCHVIEW_UPDATE_SCHEDULE in the
// process time zone. When the feature is disabled it returns immediately, so
// the default deployment has no scheduler at all.
func (s *Server) RunAutoUpdateScheduler(ctx context.Context) {
	if !s.cfg.AutoUpdate.Enabled {
		return
	}
	log.Printf("archview auto update: enabled schedule=%s timezone=%s label=%q dryRun=%v",
		s.cfg.AutoUpdate.Schedule, time.Now().Location(), s.cfg.AutoUpdate.Label, s.cfg.AutoUpdate.DryRun)
	for {
		next := nextUpdateRun(time.Now(), s.cfg.AutoUpdate.Schedule)
		log.Printf("archview auto update: next run at %s", next.Format(time.RFC3339))
		timer := time.NewTimer(time.Until(next))
		select {
		case <-ctx.Done():
			timer.Stop()
			return
		case <-timer.C:
		}
		run := s.runAutoUpdate(ctx, "schedule", false)
		if run.Error != "" {
			log.Printf("archview updates: scheduled run failed: %s", run.Error)
		}
	}
}

func (s *Server) runAutoUpdate(ctx context.Context, trigger string, force bool) (run UpdateRun) {
	s.updateRunMu.Lock()
	defer s.updateRunMu.Unlock()

	started := time.Now().UTC()
	dryRun := s.cfg.AutoUpdate.DryRun && !force
	run = UpdateRun{
		StartedAt:  started,
		Trigger:    trigger,
		DryRun:     dryRun,
		Containers: []UpdateContainerResult{},
	}

	s.setUpdateRunning(true)
	defer func() {
		run.FinishedAt = time.Now().UTC()
		s.setUpdateRunning(false)
		s.recordUpdateRun(run)
	}()

	containers, err := s.listRunningContainers(ctx)
	if err != nil {
		run.Error = "list running containers: " + err.Error()
		log.Printf("archview updates: %s run failed: %v", trigger, err)
		return run
	}

	selected, excluded := selectUpdateContainers(containers, s.cfg.AutoUpdate, updateSelfHostname())
	log.Printf("archview updates: %s run selected=%d excluded=%d dryRun=%v", trigger, len(selected), len(excluded), dryRun)
	for _, container := range selected {
		result := s.updateContainer(ctx, container, dryRun)
		if strings.HasPrefix(result.Result, updateResultFailed) {
			log.Printf("archview updates: container=%q %s", result.Name, result.Result)
		}
		run.Containers = append(run.Containers, result)
	}
	return run
}

func (s *Server) updateContainer(ctx context.Context, container updateContainer, dryRun bool) UpdateContainerResult {
	result := UpdateContainerResult{Name: container.Name}

	inspect, err := s.inspectContainer(ctx, container.ID)
	if err != nil {
		result.Result = updateFailure(err)
		return result
	}

	reference := strings.TrimSpace(container.Image)
	if reference == "" {
		reference = stringMapValue(inspect.Config, "Image")
	}
	parsed, err := parseImageReference(reference)
	if err != nil {
		result.Result = updateFailure(err)
		return result
	}

	localID := strings.TrimSpace(container.ImageID)
	if localID == "" {
		localID = strings.TrimSpace(inspect.Image)
	}
	if localID == "" {
		result.Result = updateFailure(errors.New("container has no local image ID"))
		return result
	}

	localImage, err := s.inspectImage(ctx, localID)
	if err != nil {
		result.Result = updateFailure(fmt.Errorf("inspect local image: %w", err))
		return result
	}
	oldDigest := imageRepoDigest(localImage.RepoDigests, parsed.Repository)
	if localImage.ID != "" {
		localID = localImage.ID
	}

	if err := s.pullImage(ctx, parsed); err != nil {
		result.Result = updateFailure(fmt.Errorf("pull: %w", err))
		return result
	}

	newImage, err := s.inspectImage(ctx, reference)
	if err != nil {
		result.Result = updateFailure(fmt.Errorf("inspect pulled image: %w", err))
		return result
	}
	newDigest := imageRepoDigest(newImage.RepoDigests, parsed.Repository)
	newID := strings.TrimSpace(newImage.ID)

	result.OldDigest = firstNonEmpty(oldDigest, localID)
	result.NewDigest = firstNonEmpty(newDigest, newID)

	if !decideImageChanged(oldDigest, newDigest, localID, newID) {
		result.Result = updateResultUpToDate
		return result
	}
	if dryRun {
		result.Result = updateResultWouldUpdate
		return result
	}

	if err := s.recreateContainer(ctx, inspect, reference); err != nil {
		result.Result = updateFailure(err)
		return result
	}
	result.Result = updateResultUpdated
	return result
}

func stringMapValue(values map[string]any, key string) string {
	if values == nil {
		return ""
	}
	value, _ := values[key].(string)
	return strings.TrimSpace(value)
}

func firstNonEmpty(values ...string) string {
	for _, value := range values {
		if value = strings.TrimSpace(value); value != "" {
			return value
		}
	}
	return ""
}

func updateFailure(err error) string {
	message := strings.TrimSpace(err.Error())
	message = strings.ReplaceAll(message, "\n", " ")
	message = strings.ReplaceAll(message, "\r", " ")
	if len(message) > 300 {
		message = message[:300]
	}
	return updateResultFailed + message
}

func (s *Server) pullImage(ctx context.Context, reference imageReference) error {
	query := url.Values{}
	if reference.Digest != "" {
		query.Set("fromImage", reference.Repository+"@"+reference.Digest)
	} else {
		query.Set("fromImage", reference.Repository)
		query.Set("tag", reference.Tag)
	}

	request, err := s.newDockerRequest(ctx, http.MethodPost, "/images/create?"+query.Encode(), nil)
	if err != nil {
		return err
	}
	// An empty registry-auth object keeps the call valid for anonymously
	// pullable images. Credentials stay in the daemon's own configuration.
	request.Header.Set("X-Registry-Auth", "e30=")
	request.Header.Set("Content-Type", "application/json")

	response, err := s.dockerHTTPClient().Do(request)
	if err != nil {
		return err
	}
	defer response.Body.Close()

	if response.StatusCode >= 300 {
		body, _ := io.ReadAll(io.LimitReader(response.Body, 2048))
		return fmt.Errorf("docker api %s returned %s: %s", request.URL.Path, response.Status, strings.TrimSpace(string(body)))
	}

	// /images/create streams newline-delimited progress. Errors may arrive
	// inside a 200 response, so scan every message rather than only checking
	// the status code.
	scanner := bufio.NewScanner(response.Body)
	scanner.Buffer(make([]byte, 64*1024), 1024*1024)
	for scanner.Scan() {
		var message struct {
			Error       string `json:"error"`
			ErrorDetail struct {
				Message string `json:"message"`
			} `json:"errorDetail"`
		}
		if err := json.Unmarshal(scanner.Bytes(), &message); err != nil {
			continue
		}
		if message.Error != "" {
			return errors.New(message.Error)
		}
		if message.ErrorDetail.Message != "" {
			return errors.New(message.ErrorDetail.Message)
		}
	}
	if err := scanner.Err(); err != nil {
		return fmt.Errorf("read image pull response: %w", err)
	}
	return nil
}

func (s *Server) recreateContainer(ctx context.Context, inspect dockerContainerInspectFull, imageReference string) error {
	body, err := buildContainerCreateBody(inspect, imageReference)
	if err != nil {
		return err
	}

	name := strings.TrimPrefix(inspect.Name, "/")
	stopTimeout := 10
	if timeout, ok := inspect.HostConfig["StopTimeout"].(float64); ok && timeout > 0 {
		stopTimeout = int(timeout)
	}

	status, err := s.dockerRequest(ctx, http.MethodPost,
		"/containers/"+url.PathEscape(inspect.ID)+"/stop?t="+strconv.Itoa(stopTimeout), nil, nil)
	if err != nil && status != http.StatusNotModified {
		return fmt.Errorf("stop container: %w", err)
	}

	status, err = s.dockerRequest(ctx, http.MethodDelete,
		"/containers/"+url.PathEscape(inspect.ID)+"?v=0&force=0", nil, nil)
	if err != nil && status != http.StatusNotFound {
		return fmt.Errorf("remove container: %w", err)
	}

	createPath := "/containers/create"
	if name != "" {
		createPath += "?name=" + url.QueryEscape(name)
	}
	var created struct {
		ID string `json:"Id"`
	}
	if _, err := s.dockerRequest(ctx, http.MethodPost, createPath, bytes.NewReader(body), &created); err != nil {
		return fmt.Errorf("create container: %w", err)
	}
	if strings.TrimSpace(created.ID) == "" {
		return errors.New("create container: Docker returned no container ID")
	}

	if _, err := s.dockerRequest(ctx, http.MethodPost, "/containers/"+url.PathEscape(created.ID)+"/start", nil, nil); err != nil {
		return fmt.Errorf("start container: %w", err)
	}
	return nil
}

// buildContainerCreateBody rebuilds the Docker create request from the
// inspected container. Config and HostConfig are copied verbatim so env,
// mounts, port bindings, restart policy, labels and resource limits survive the
// recreation; only the image reference is replaced.
func buildContainerCreateBody(inspect dockerContainerInspectFull, imageReference string) ([]byte, error) {
	body := make(map[string]any, len(inspect.Config)+3)
	for key, value := range inspect.Config {
		body[key] = value
	}
	body["Image"] = imageReference
	// Docker writes the container ID into Config.Hostname when the operator did
	// not set one. Copying that back would freeze the old ID as the new
	// container's hostname; let Docker assign the new ID instead.
	if hostname := stringMapValue(inspect.Config, "Hostname"); hostname != "" && sameContainerID(inspect.ID, hostname) {
		body["Hostname"] = ""
	}
	if inspect.HostConfig != nil {
		body["HostConfig"] = inspect.HostConfig
	}
	if networkingConfig := buildNetworkingConfig(inspect); networkingConfig != nil {
		body["NetworkingConfig"] = networkingConfig
	}

	encoded, err := json.Marshal(body)
	if err != nil {
		return nil, fmt.Errorf("encode container config: %w", err)
	}
	return encoded, nil
}

func buildNetworkingConfig(inspect dockerContainerInspectFull) map[string]any {
	mode := stringMapValue(inspect.HostConfig, "NetworkMode")
	if mode == "host" || mode == "none" || strings.HasPrefix(mode, "container:") {
		return nil
	}
	if len(inspect.NetworkSettings.Networks) == 0 {
		return nil
	}
	return map[string]any{"EndpointsConfig": inspect.NetworkSettings.Networks}
}

func (s *Server) handleUpdates(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		w.Header().Set("Allow", http.MethodGet)
		writeJSON(w, http.StatusMethodNotAllowed, map[string]any{"error": "method not allowed"})
		return
	}
	writeJSON(w, http.StatusOK, s.updateStatus(r.Context(), true))
}

func (s *Server) handleUpdatesRun(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		w.Header().Set("Allow", http.MethodPost)
		writeJSON(w, http.StatusMethodNotAllowed, map[string]any{"error": "method not allowed"})
		return
	}
	if !s.authorizeUpdateAdmin(w, r) {
		return
	}

	var request struct {
		Force bool `json:"force"`
	}
	if r.Body != nil {
		decoder := json.NewDecoder(io.LimitReader(r.Body, 64*1024))
		if err := decoder.Decode(&request); err != nil && !errors.Is(err, io.EOF) {
			writeJSON(w, http.StatusBadRequest, map[string]any{"error": "invalid JSON body: " + err.Error()})
			return
		}
	}

	run := s.runAutoUpdate(r.Context(), "manual", request.Force)
	status := http.StatusOK
	if run.Error != "" {
		status = http.StatusBadGateway
	}
	writeJSON(w, status, run)
}

// authorizeUpdateAdmin applies the same administrator rule as the destructive
// endpoint-management route. The updater stops and recreates containers, so a
// read-only token must not be able to trigger it.
func (s *Server) authorizeUpdateAdmin(w http.ResponseWriter, r *http.Request) bool {
	refuse := func(status int, code, message string) bool {
		log.Printf("archview updates: manual run refused principal=%q reason=%q",
			updatePrincipalIdentity(r), message)
		writeJSON(w, status, map[string]any{"error": code, "message": message})
		return false
	}

	if !s.auth.Enabled() {
		return true
	}
	principal, ok := PrincipalFromContext(r.Context())
	if !ok {
		return refuse(http.StatusUnauthorized, "unauthorized", "authentication required")
	}
	if len(s.cfg.EndpointAdminEmails) == 0 && len(s.cfg.EndpointAdminClients) == 0 {
		return refuse(http.StatusForbidden, "update administration is not configured",
			"set ENDPOINTS_ADMIN_EMAILS or ENDPOINTS_ADMIN_CLIENTS to allow manual update runs")
	}
	if principal.Method == "client_credentials" {
		if !containsFold(s.cfg.EndpointAdminClients, principal.Name) {
			return refuse(http.StatusForbidden, "forbidden",
				"this client is not listed in ENDPOINTS_ADMIN_CLIENTS")
		}
		scope := strings.TrimSpace(s.cfg.EndpointAdminScope)
		if scope == "" {
			scope = defaultEndpointAdminScope
		}
		if !scopeContainsAll(principal.Scopes, []string{scope}) {
			return refuse(http.StatusForbidden, "forbidden",
				fmt.Sprintf("this client token does not carry the %q scope required by ENDPOINTS_ADMIN_SCOPE", scope))
		}
		return true
	}
	if principal.Email != "" && containsFold(s.cfg.EndpointAdminEmails, principal.Email) {
		return true
	}
	return refuse(http.StatusForbidden, "forbidden", "this account is not allowed to run container updates")
}

func updatePrincipalIdentity(r *http.Request) string {
	principal, _ := PrincipalFromContext(r.Context())
	return endpointPrincipalIdentity(principal)
}

var updatesPageTemplate = template.Must(template.New("updates").Parse(`<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>ArchView auto updates</title>
  <style>
    body{font-family:ui-monospace,SFMono-Regular,Menlo,monospace;max-width:72rem;margin:2rem auto;padding:0 1rem;color:#1f2933;background:#fbfcfd}
    h1{font-size:1.4rem} h2{font-size:1.1rem;margin-top:2rem}
    dl{display:grid;grid-template-columns:max-content 1fr;gap:.35rem 1.5rem}
    dt{font-weight:600} dd{margin:0}
    table{border-collapse:collapse;width:100%;margin-top:.75rem}
    th,td{text-align:left;padding:.45rem .6rem;border-bottom:1px solid #d9e2ec;vertical-align:top}
    th{background:#f0f4f8} .muted{color:#627d98}
  </style>
</head>
<body>
  <h1>Automatic container updates</h1>
  <dl>
    <dt>Enabled</dt><dd>{{if .Enabled}}yes{{else}}no{{end}}</dd>
    <dt>Dry run</dt><dd>{{if .DryRun}}yes (pulls and compares, never recreates){{else}}no{{end}}</dd>
    <dt>Schedule</dt><dd>{{.Schedule}} ({{.Timezone}})</dd>
    <dt>Next run</dt><dd>{{if .NextRun}}{{.NextRun}}{{else}}not scheduled{{end}}</dd>
    <dt>Label</dt><dd>{{.Label}}</dd>
    <dt>State</dt><dd>{{if .Running}}running now{{else}}idle{{end}}</dd>
  </dl>

  <h2>Last run</h2>
  {{if .Last}}
  <dl>
    <dt>Started</dt><dd>{{.Last.StartedAt.Format "2006-01-02 15:04:05 MST"}}</dd>
    <dt>Finished</dt><dd>{{.Last.FinishedAt.Format "2006-01-02 15:04:05 MST"}}</dd>
    <dt>Trigger</dt><dd>{{.Last.Trigger}}</dd>
    <dt>Mode</dt><dd>{{if .Last.DryRun}}dry run{{else}}live{{end}}</dd>
    {{if .Last.Error}}<dt>Error</dt><dd>{{.Last.Error}}</dd>{{end}}
  </dl>
  <table>
    <thead><tr><th>Container</th><th>Old digest</th><th>New digest</th><th>Outcome</th></tr></thead>
    <tbody>
      {{range .Last.Containers}}
      <tr><td>{{.Name}}</td><td>{{.OldDigest}}</td><td>{{.NewDigest}}</td><td>{{.Result}}</td></tr>
      {{else}}
      <tr><td colspan="4" class="muted">No containers were selected.</td></tr>
      {{end}}
    </tbody>
  </table>
  {{else}}
  <p class="muted">No runs recorded yet.</p>
  {{end}}
  <p class="muted">Read-only view. This page does not trigger updates or load any scripts.</p>
</body>
</html>`))

func (s *Server) handleUpdatesDashboard(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path != "/updates" {
		http.NotFound(w, r)
		return
	}
	if r.Method != http.MethodGet {
		w.Header().Set("Allow", http.MethodGet)
		writeJSON(w, http.StatusMethodNotAllowed, map[string]any{"error": "method not allowed"})
		return
	}

	status := s.updateStatus(r.Context(), false)
	var last *UpdateRun
	if len(status.Runs) > 0 {
		last = &status.Runs[0]
	}
	data := struct {
		UpdatesResponse
		Last     *UpdateRun
		Timezone string
	}{
		UpdatesResponse: status,
		Last:            last,
		Timezone:        time.Now().Location().String(),
	}

	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	if err := updatesPageTemplate.Execute(w, data); err != nil {
		log.Printf("archview updates: render dashboard: %v", err)
	}
}
