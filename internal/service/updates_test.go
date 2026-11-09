package service

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"
)

func TestSelectUpdateContainers(t *testing.T) {
	selfID := "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
	containers := []dockerContainer{
		{ID: "web-id", Names: []string{"/web"}, Labels: map[string]string{"archview.update": "auto"}},
		{ID: "db-id", Names: []string{"/db"}},
		{ID: "worker-id", Names: []string{"/worker"}, Labels: map[string]string{"archview.update": "manual"}},
		{ID: "archview-id", Names: []string{"/archview"}, Labels: map[string]string{"archview.update": "auto"}},
		{ID: "proxy-id", Names: []string{"/paseo-socket-proxy-1"}, Labels: map[string]string{"archview.update": "auto"}},
		{ID: "watchtower-id", Names: []string{"/watchtower"}, Labels: map[string]string{"archview.update": "auto"}},
		{ID: "game-db-id", Names: []string{"/game-db"}, Labels: map[string]string{"archview.update": "auto"}},
		{ID: selfID[:12], Names: []string{"/custom-name"}, Labels: map[string]string{"archview.update": "auto"}},
	}

	selected, excluded := selectUpdateContainers(containers, AutoUpdateConfig{
		Label:   defaultUpdateLabel,
		Exclude: []string{"game-db"},
	}, selfID)

	if len(selected) != 1 || selected[0].Name != "web" {
		t.Fatalf("selected = %+v, want only web", selected)
	}

	reasons := make(map[string]string, len(excluded))
	for _, entry := range excluded {
		reasons[entry.Name] = entry.Reason
	}
	want := map[string]string{
		"archview":             "archview",
		"paseo-socket-proxy-1": "socket proxy",
		"watchtower":           "watchtower",
		"game-db":              "configured exclusion",
		"custom-name":          "archview",
	}
	if len(reasons) != len(want) {
		t.Fatalf("excluded = %+v, want %d entries", excluded, len(want))
	}
	for name, reason := range want {
		if reasons[name] != reason {
			t.Fatalf("excluded[%q] = %q, want %q (all: %+v)", name, reasons[name], reason, excluded)
		}
	}
}

func TestSelectUpdateContainersLabelValue(t *testing.T) {
	containers := []dockerContainer{
		{ID: "a", Names: []string{"/any"}, Labels: map[string]string{"archview.update": "anything"}},
		{ID: "b", Names: []string{"/other"}, Labels: map[string]string{"different.label": "auto"}},
	}
	selected, _ := selectUpdateContainers(containers, AutoUpdateConfig{Label: "archview.update"}, "not-a-container-id")
	if len(selected) != 1 || selected[0].Name != "any" {
		t.Fatalf("key-only label selected = %+v, want any", selected)
	}
}

func TestDecideImageChanged(t *testing.T) {
	tests := []struct {
		name                               string
		oldDigest, newDigest, oldID, newID string
		want                               bool
	}{
		{name: "same digest is up to date", oldDigest: "sha256:a", newDigest: "sha256:a", oldID: "sha256:1", newID: "sha256:1", want: false},
		{name: "different digest is an update", oldDigest: "sha256:a", newDigest: "sha256:b", oldID: "sha256:1", newID: "sha256:2", want: true},
		{name: "same image ID without digests is up to date", oldID: "sha256:1", newID: "sha256:1", want: false},
		{name: "missing old digest but same ID is up to date", newDigest: "sha256:a", oldID: "sha256:1", newID: "sha256:1", want: false},
		{name: "different IDs without digests is an update", oldID: "sha256:1", newID: "sha256:2", want: true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := decideImageChanged(tt.oldDigest, tt.newDigest, tt.oldID, tt.newID); got != tt.want {
				t.Fatalf("decideImageChanged() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestParseImageReference(t *testing.T) {
	tests := []struct {
		raw  string
		repo string
		tag  string
	}{
		{raw: "nginx", repo: "nginx", tag: "latest"},
		{raw: "nginx:1.27", repo: "nginx", tag: "1.27"},
		{raw: "ghcr.io/acme/app:v2", repo: "ghcr.io/acme/app", tag: "v2"},
		{raw: "registry.example:5000/acme/app", repo: "registry.example:5000/acme/app", tag: "latest"},
	}
	for _, tt := range tests {
		got, err := parseImageReference(tt.raw)
		if err != nil {
			t.Fatalf("parseImageReference(%q): %v", tt.raw, err)
		}
		if got.Repository != tt.repo || got.Tag != tt.tag {
			t.Fatalf("parseImageReference(%q) = repo %q tag %q, want %q %q", tt.raw, got.Repository, got.Tag, tt.repo, tt.tag)
		}
	}

	if _, err := parseImageReference("sha256:" + strings.Repeat("a", 64)); err == nil {
		t.Fatal("image ID should not be treated as a pullable reference")
	}
}

func TestNextUpdateRun(t *testing.T) {
	location := time.FixedZone("TEST", 2*60*60)
	now := time.Date(2026, 11, 9, 3, 15, 0, 0, location)
	next := nextUpdateRun(now, "04:30")
	if want := time.Date(2026, 11, 9, 4, 30, 0, 0, location); !next.Equal(want) {
		t.Fatalf("next = %s, want %s", next, want)
	}

	now = time.Date(2026, 11, 9, 5, 0, 0, 0, location)
	next = nextUpdateRun(now, "04:30")
	if want := time.Date(2026, 11, 10, 4, 30, 0, 0, location); !next.Equal(want) {
		t.Fatalf("next after today's time = %s, want %s", next, want)
	}
}

// updateDockerFixture is a fake Docker API. It serves a container listing,
// per-container inspects and image inspects, and records the write calls the
// updater makes. No real daemon is involved.
type updateDockerFixture struct {
	mu          sync.Mutex
	containers  []map[string]any
	inspect     map[string]map[string]any
	pullFailure map[string]bool
	images      map[string]dockerImageInspect
	newImages   map[string]dockerImageInspect
	pulled      map[string]int
	calls       []string
	createBody  map[string]any
	createCount int
	startCount  int
	stopCount   int
	removeCount int
}

func newUpdateDockerFixture(t *testing.T) (*updateDockerFixture, *httptest.Server) {
	t.Helper()
	fixture := &updateDockerFixture{
		inspect:     map[string]map[string]any{},
		pullFailure: map[string]bool{},
		images:      map[string]dockerImageInspect{},
		newImages:   map[string]dockerImageInspect{},
		pulled:      map[string]int{},
	}
	server := httptest.NewServer(http.HandlerFunc(fixture.serveHTTP))
	t.Cleanup(server.Close)
	return fixture, server
}

func (f *updateDockerFixture) serveHTTP(w http.ResponseWriter, r *http.Request) {
	path := strings.TrimPrefix(r.URL.Path, "/v1.41")
	f.mu.Lock()
	f.calls = append(f.calls, r.Method+" "+path)
	f.mu.Unlock()

	switch {
	case r.Method == http.MethodGet && path == "/containers/json":
		f.mu.Lock()
		payload := append([]map[string]any(nil), f.containers...)
		f.mu.Unlock()
		writeFixtureJSON(w, payload)

	case strings.HasPrefix(path, "/containers/") && strings.HasSuffix(path, "/json"):
		id := strings.TrimSuffix(strings.TrimPrefix(path, "/containers/"), "/json")
		f.mu.Lock()
		inspect := f.inspect[id]
		f.mu.Unlock()
		if inspect == nil {
			http.NotFound(w, r)
			return
		}
		writeFixtureJSON(w, inspect)

	case r.Method == http.MethodPost && path == "/images/create":
		reference := r.URL.Query().Get("fromImage")
		if tag := r.URL.Query().Get("tag"); tag != "" {
			reference += ":" + tag
		}
		f.mu.Lock()
		f.pulled[reference]++
		failed := f.pullFailure[reference]
		f.mu.Unlock()
		if failed {
			http.Error(w, `{"message":"registry rejected the pull"}`, http.StatusInternalServerError)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = io.WriteString(w, `{"status":"Pulled"}`+"\n")

	case strings.HasPrefix(path, "/images/") && strings.HasSuffix(path, "/json"):
		reference := strings.TrimSuffix(strings.TrimPrefix(path, "/images/"), "/json")
		f.mu.Lock()
		image, ok := f.images[reference]
		if f.pulled[reference] > 0 {
			if pulled, found := f.newImages[reference]; found {
				image, ok = pulled, true
			}
		}
		f.mu.Unlock()
		if !ok {
			http.NotFound(w, r)
			return
		}
		writeFixtureJSON(w, image)

	case r.Method == http.MethodPost && strings.HasSuffix(path, "/stop"):
		f.mu.Lock()
		f.stopCount++
		f.mu.Unlock()
		w.WriteHeader(http.StatusNoContent)

	case r.Method == http.MethodDelete && strings.HasPrefix(path, "/containers/"):
		f.mu.Lock()
		f.removeCount++
		f.mu.Unlock()
		w.WriteHeader(http.StatusNoContent)

	case r.Method == http.MethodPost && path == "/containers/create":
		var body map[string]any
		_ = json.NewDecoder(r.Body).Decode(&body)
		f.mu.Lock()
		f.createBody = body
		f.createCount++
		f.mu.Unlock()
		writeFixtureJSON(w, map[string]any{"Id": "new-web-id"})

	case r.Method == http.MethodPost && strings.HasSuffix(path, "/start"):
		f.mu.Lock()
		f.startCount++
		f.mu.Unlock()
		w.WriteHeader(http.StatusNoContent)

	default:
		http.NotFound(w, r)
	}
}

func writeFixtureJSON(w http.ResponseWriter, payload any) {
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(payload)
}

func addWebFixture(fixture *updateDockerFixture, newDigest string) {
	fixture.containers = []map[string]any{
		{
			"Id":      "web-id",
			"Names":   []string{"/web"},
			"Image":   "registry.example/web:latest",
			"ImageID": "sha256:oldweb",
			"Labels":  map[string]string{"archview.update": "auto"},
		},
	}
	fixture.inspect["web-id"] = map[string]any{
		"Id":    "web-id",
		"Name":  "/web",
		"Image": "sha256:oldweb",
		"Config": map[string]any{
			"Image":  "registry.example/web:latest",
			"Env":    []string{"APP_ENV=production", "SECRET_FROM_HOST=kept"},
			"Labels": map[string]string{"archview.update": "auto", "team": "fleet"},
		},
		"HostConfig": map[string]any{
			"RestartPolicy": map[string]any{"Name": "unless-stopped"},
			"Binds":         []string{"/srv/web:/srv/web:ro"},
			"NetworkMode":   "bridge",
		},
		"NetworkSettings": map[string]any{
			"Networks": map[string]any{"bridge": map[string]any{"Aliases": nil}},
		},
	}
	fixture.images["sha256:oldweb"] = dockerImageInspect{
		ID:          "sha256:oldweb",
		RepoDigests: []string{"registry.example/web@sha256:old"},
	}
	fixture.images["registry.example/web:latest"] = dockerImageInspect{
		ID:          "sha256:oldweb",
		RepoDigests: []string{"registry.example/web@sha256:old"},
	}
	fixture.newImages["registry.example/web:latest"] = dockerImageInspect{
		ID:          "sha256:newweb",
		RepoDigests: []string{"registry.example/web@" + newDigest},
	}
}

func newUpdateTestServer(t *testing.T, dockerURL string, autoUpdate AutoUpdateConfig) *Server {
	t.Helper()
	server, err := NewServer(Config{
		DockerAPI:  "v1.41",
		DockerHost: dockerURL,
		Auth:       AuthConfig{Mode: authModeNone},
		AutoUpdate: autoUpdate,
	})
	if err != nil {
		t.Fatalf("NewServer: %v", err)
	}
	return server
}

func TestRunAutoUpdateKeepsGoingAfterFailureAndHonoursDryRun(t *testing.T) {
	fixture, docker := newUpdateDockerFixture(t)
	addWebFixture(fixture, "sha256:new")
	// The failing container is first in the listing: the run must still reach web.
	fixture.containers = []map[string]any{
		{
			"Id":      "bad-id",
			"Names":   []string{"/bad"},
			"Image":   "registry.example/bad:latest",
			"ImageID": "sha256:oldbad",
			"Labels":  map[string]string{"archview.update": "auto"},
		},
		fixture.containers[0],
	}
	fixture.inspect["bad-id"] = map[string]any{
		"Id":         "bad-id",
		"Name":       "/bad",
		"Image":      "sha256:oldbad",
		"Config":     map[string]any{"Image": "registry.example/bad:latest"},
		"HostConfig": map[string]any{"NetworkMode": "bridge"},
	}
	fixture.images["sha256:oldbad"] = dockerImageInspect{
		ID:          "sha256:oldbad",
		RepoDigests: []string{"registry.example/bad@sha256:old"},
	}
	fixture.pullFailure["registry.example/bad:latest"] = true

	server := newUpdateTestServer(t, docker.URL, AutoUpdateConfig{
		Enabled:  true,
		Schedule: defaultUpdateSchedule,
		Label:    defaultUpdateLabel,
		DryRun:   true,
	})
	run := server.runAutoUpdate(context.Background(), "manual", false)

	if len(run.Containers) != 2 {
		t.Fatalf("got %d container results, want 2: %+v", len(run.Containers), run.Containers)
	}
	if !strings.HasPrefix(run.Containers[0].Result, updateResultFailed) {
		t.Fatalf("bad container result = %q, want failed", run.Containers[0].Result)
	}
	if run.Containers[1].Name != "web" || run.Containers[1].Result != updateResultWouldUpdate {
		t.Fatalf("web result = %+v, want would-update", run.Containers[1])
	}
	if run.DryRun != true {
		t.Fatal("run should report dry-run")
	}
	if fixture.createCount != 0 || fixture.stopCount != 0 || fixture.removeCount != 0 || fixture.startCount != 0 {
		t.Fatalf("dry run performed write calls: create=%d stop=%d remove=%d start=%d",
			fixture.createCount, fixture.stopCount, fixture.removeCount, fixture.startCount)
	}
	if fixture.pulled["registry.example/web:latest"] != 1 {
		t.Fatalf("pull count = %d, want 1", fixture.pulled["registry.example/web:latest"])
	}
}

func TestRunAutoUpdateRecreatesChangedContainer(t *testing.T) {
	fixture, docker := newUpdateDockerFixture(t)
	addWebFixture(fixture, "sha256:new")

	server := newUpdateTestServer(t, docker.URL, AutoUpdateConfig{
		Enabled:  true,
		Schedule: defaultUpdateSchedule,
		Label:    defaultUpdateLabel,
	})
	run := server.runAutoUpdate(context.Background(), "manual", false)

	if len(run.Containers) != 1 {
		t.Fatalf("got %d results, want 1: %+v", len(run.Containers), run.Containers)
	}
	result := run.Containers[0]
	if result.Result != updateResultUpdated {
		t.Fatalf("result = %q, want updated", result.Result)
	}
	if result.OldDigest != "sha256:old" || result.NewDigest != "sha256:new" {
		t.Fatalf("digests = %q -> %q, want sha256:old -> sha256:new", result.OldDigest, result.NewDigest)
	}
	if fixture.stopCount != 1 || fixture.removeCount != 1 || fixture.createCount != 1 || fixture.startCount != 1 {
		t.Fatalf("write calls = stop %d remove %d create %d start %d, want one each",
			fixture.stopCount, fixture.removeCount, fixture.createCount, fixture.startCount)
	}

	body := fixture.createBody
	if body["Image"] != "registry.example/web:latest" {
		t.Fatalf("create Image = %v, want the resolved reference", body["Image"])
	}
	env, _ := body["Env"].([]any)
	if len(env) != 2 || env[0] != "APP_ENV=production" {
		t.Fatalf("create Env = %v, want the inspected environment", body["Env"])
	}
	labels, _ := body["Labels"].(map[string]any)
	if labels["team"] != "fleet" || labels["archview.update"] != "auto" {
		t.Fatalf("create Labels = %v, want inspected labels", body["Labels"])
	}
	hostConfig, _ := body["HostConfig"].(map[string]any)
	restart, _ := hostConfig["RestartPolicy"].(map[string]any)
	if restart["Name"] != "unless-stopped" {
		t.Fatalf("create RestartPolicy = %v, want unless-stopped", hostConfig["RestartPolicy"])
	}
	binds, _ := hostConfig["Binds"].([]any)
	if len(binds) != 1 || binds[0] != "/srv/web:/srv/web:ro" {
		t.Fatalf("create Binds = %v, want the inspected bind mount", hostConfig["Binds"])
	}
}

func TestRunAutoUpdateUpToDateDoesNotRecreate(t *testing.T) {
	fixture, docker := newUpdateDockerFixture(t)
	addWebFixture(fixture, "sha256:old")
	fixture.newImages["registry.example/web:latest"] = dockerImageInspect{
		ID:          "sha256:oldweb",
		RepoDigests: []string{"registry.example/web@sha256:old"},
	}

	server := newUpdateTestServer(t, docker.URL, AutoUpdateConfig{
		Enabled:  true,
		Schedule: defaultUpdateSchedule,
		Label:    defaultUpdateLabel,
	})
	run := server.runAutoUpdate(context.Background(), "manual", false)
	if len(run.Containers) != 1 || run.Containers[0].Result != updateResultUpToDate {
		t.Fatalf("run = %+v, want one up-to-date result", run.Containers)
	}
	if fixture.createCount != 0 || fixture.stopCount != 0 {
		t.Fatalf("up-to-date container was recreated: create=%d stop=%d", fixture.createCount, fixture.stopCount)
	}
}

func TestUpdatesStatusEndpoint(t *testing.T) {
	fixture, docker := newUpdateDockerFixture(t)
	addWebFixture(fixture, "sha256:new")
	server := newUpdateTestServer(t, docker.URL, AutoUpdateConfig{
		Enabled:  true,
		Schedule: "04:30",
		Label:    defaultUpdateLabel,
		DryRun:   true,
	})
	handler := server.Routes()

	request := httptest.NewRequest(http.MethodGet, "https://archview.example/api/updates", nil)
	recorder := httptest.NewRecorder()
	handler.ServeHTTP(recorder, request)

	if recorder.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200 (body %s)", recorder.Code, recorder.Body.String())
	}
	var response UpdatesResponse
	if err := json.Unmarshal(recorder.Body.Bytes(), &response); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if !response.Enabled || !response.DryRun {
		t.Fatalf("response = %+v, want enabled dry-run", response)
	}
	if response.NextRun == nil {
		t.Fatal("nextRun is nil for an enabled schedule")
	}
	if len(response.Selection.OptedIn) != 1 || response.Selection.OptedIn[0] != "web" {
		t.Fatalf("selection = %+v, want web opted in", response.Selection)
	}
	if response.Runs == nil || len(response.Runs) != 0 {
		t.Fatalf("runs = %+v, want an empty non-nil list", response.Runs)
	}
}

func TestUpdatesRunEndpointForceOverridesDryRun(t *testing.T) {
	fixture, docker := newUpdateDockerFixture(t)
	addWebFixture(fixture, "sha256:new")
	server := newUpdateTestServer(t, docker.URL, AutoUpdateConfig{
		Enabled:  true,
		Schedule: defaultUpdateSchedule,
		Label:    defaultUpdateLabel,
		DryRun:   true,
	})
	handler := server.Routes()

	request := httptest.NewRequest(http.MethodPost, "https://archview.example/api/updates/run",
		strings.NewReader(`{"force":true}`))
	request.Header.Set("Content-Type", "application/json")
	recorder := httptest.NewRecorder()
	handler.ServeHTTP(recorder, request)

	if recorder.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200 (body %s)", recorder.Code, recorder.Body.String())
	}
	var run UpdateRun
	if err := json.Unmarshal(recorder.Body.Bytes(), &run); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if run.DryRun {
		t.Fatal("force=true should override the configured dry run")
	}
	if run.FinishedAt.IsZero() {
		t.Fatal("returned run has no finishedAt timestamp")
	}
	if len(run.Containers) != 1 || run.Containers[0].Result != updateResultUpdated {
		t.Fatalf("run = %+v, want one updated container", run)
	}
	if fixture.createCount != 1 {
		t.Fatalf("create count = %d, want 1", fixture.createCount)
	}
}

func TestUpdatesDashboardShowsLastRun(t *testing.T) {
	_, docker := newUpdateDockerFixture(t)
	server := newUpdateTestServer(t, docker.URL, AutoUpdateConfig{
		Enabled:  true,
		Schedule: defaultUpdateSchedule,
		Label:    defaultUpdateLabel,
	})
	server.updateRuns = []UpdateRun{{
		StartedAt:  time.Date(2026, 11, 9, 4, 30, 0, 0, time.UTC),
		FinishedAt: time.Date(2026, 11, 9, 4, 31, 0, 0, time.UTC),
		Trigger:    "schedule",
		Containers: []UpdateContainerResult{{
			Name:      "web",
			OldDigest: "sha256:old",
			NewDigest: "sha256:new",
			Result:    updateResultUpdated,
		}},
	}}

	request := httptest.NewRequest(http.MethodGet, "https://archview.example/updates", nil)
	recorder := httptest.NewRecorder()
	server.handleUpdatesDashboard(recorder, request)

	if recorder.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", recorder.Code)
	}
	if contentType := recorder.Header().Get("Content-Type"); !strings.HasPrefix(contentType, "text/html") {
		t.Fatalf("content type = %q, want text/html", contentType)
	}
	body := recorder.Body.String()
	for _, want := range []string{"web", "sha256:old", "sha256:new", updateResultUpdated} {
		if !strings.Contains(body, want) {
			t.Fatalf("dashboard body is missing %q", want)
		}
	}
}
