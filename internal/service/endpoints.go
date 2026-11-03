package service

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/url"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"
)

// defaultEndpointAdminScope is the permission a machine token must carry to
// call the destructive endpoint-management routes. It is deliberately narrower
// than the read scope used for telemetry.
const defaultEndpointAdminScope = "endpoints:admin"

// ManagedEndpoint is one host reachable through the Portainer hub. Key is the
// stable name used in ArchView URLs; PortainerEndpointID is the numeric id that
// Portainer gives the same host.
type ManagedEndpoint struct {
	Key                 string `json:"key"`
	PortainerEndpointID int    `json:"portainerEndpointId"`
}

// PrunedImage is one image removed by Docker's images/prune call. Docker sets
// either Deleted (image id) or Untagged (repo:tag) on each entry.
type PrunedImage struct {
	Deleted  string `json:"deleted,omitempty"`
	Untagged string `json:"untagged,omitempty"`
}

// PruneImagesResponse is the per-endpoint result of an image prune.
type PruneImagesResponse struct {
	Endpoint            string        `json:"endpoint"`
	PortainerEndpointID int           `json:"portainerEndpointId"`
	Mode                string        `json:"mode"`
	ImagesDeleted       []PrunedImage `json:"imagesDeleted"`
	DeletedCount        int           `json:"deletedCount"`
	SpaceReclaimedBytes int64         `json:"spaceReclaimedBytes"`
}

type portainerPruneResponse struct {
	ImagesDeleted []struct {
		Deleted  string `json:"Deleted"`
		Untagged string `json:"Untagged"`
	} `json:"ImagesDeleted"`
	SpaceReclaimed int64 `json:"SpaceReclaimed"`
}

var endpointKeyPattern = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]*$`)

// ParseEndpoints parses the ENDPOINTS configuration. Three forms are accepted:
//
//   - comma-separated key=id pairs: rossmoney=1,host2=2
//   - a JSON array: [{"key":"rossmoney","portainerEndpointId":1}]
//   - a JSON object: {"rossmoney":1,"host2":2}
//
// An empty value means "no managed endpoints" and is not an error.
func ParseEndpoints(raw string) ([]ManagedEndpoint, error) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return nil, nil
	}

	var endpoints []ManagedEndpoint
	if strings.HasPrefix(raw, "[") || strings.HasPrefix(raw, "{") {
		parsed, err := parseEndpointsJSON(raw)
		if err != nil {
			return nil, err
		}
		endpoints = parsed
	} else {
		for _, entry := range strings.Split(raw, ",") {
			entry = strings.TrimSpace(entry)
			if entry == "" {
				continue
			}
			key, id, ok := strings.Cut(entry, "=")
			if !ok {
				return nil, fmt.Errorf("invalid endpoint %q: want key=portainer-endpoint-id", entry)
			}
			key = strings.TrimSpace(key)
			id = strings.TrimSpace(id)
			if !endpointKeyPattern.MatchString(key) {
				return nil, fmt.Errorf("invalid endpoint key %q: use letters, digits, dot, dash or underscore", key)
			}
			number, err := strconv.Atoi(id)
			if err != nil || number <= 0 {
				return nil, fmt.Errorf("invalid Portainer endpoint id %q for %q: want a positive integer", id, key)
			}
			endpoints = append(endpoints, ManagedEndpoint{Key: key, PortainerEndpointID: number})
		}
	}

	if err := validateEndpointRegistry(endpoints); err != nil {
		return nil, err
	}
	sort.Slice(endpoints, func(i, j int) bool { return endpoints[i].Key < endpoints[j].Key })
	return endpoints, nil
}

func parseEndpointsJSON(raw string) ([]ManagedEndpoint, error) {
	if strings.HasPrefix(raw, "[") {
		var endpoints []ManagedEndpoint
		if err := json.Unmarshal([]byte(raw), &endpoints); err != nil {
			return nil, fmt.Errorf("invalid ENDPOINTS JSON array: %w", err)
		}
		return endpoints, nil
	}

	var byKey map[string]int
	if err := json.Unmarshal([]byte(raw), &byKey); err != nil {
		return nil, fmt.Errorf("invalid ENDPOINTS JSON object: %w", err)
	}
	endpoints := make([]ManagedEndpoint, 0, len(byKey))
	for key, id := range byKey {
		endpoints = append(endpoints, ManagedEndpoint{Key: key, PortainerEndpointID: id})
	}
	return endpoints, nil
}

func validateEndpointRegistry(endpoints []ManagedEndpoint) error {
	seen := make(map[string]struct{}, len(endpoints))
	for _, endpoint := range endpoints {
		if !endpointKeyPattern.MatchString(endpoint.Key) {
			return fmt.Errorf("invalid endpoint key %q: use letters, digits, dot, dash or underscore", endpoint.Key)
		}
		if endpoint.PortainerEndpointID <= 0 {
			return fmt.Errorf("invalid Portainer endpoint id %d for %q: want a positive integer", endpoint.PortainerEndpointID, endpoint.Key)
		}
		if _, ok := seen[endpoint.Key]; ok {
			return fmt.Errorf("duplicate endpoint key %q", endpoint.Key)
		}
		seen[endpoint.Key] = struct{}{}
	}
	return nil
}

func validatePortainerURL(raw string) error {
	parsed, err := url.Parse(strings.TrimSpace(raw))
	if err != nil {
		return fmt.Errorf("invalid PORTAINER_URL: %w", err)
	}
	if parsed.Scheme != "http" && parsed.Scheme != "https" {
		return fmt.Errorf("invalid PORTAINER_URL %q: scheme must be http or https", raw)
	}
	if parsed.Host == "" {
		return fmt.Errorf("invalid PORTAINER_URL %q: host is required", raw)
	}
	return nil
}

func newPortainerClient(insecureSkipVerify bool) *http.Client {
	transport := &http.Transport{}
	if insecureSkipVerify {
		transport.TLSClientConfig = &tls.Config{InsecureSkipVerify: true} //nolint:gosec // explicit opt-in for a self-signed hub
	}
	return &http.Client{Transport: transport, Timeout: 60 * time.Second}
}

// handleEndpointRoute dispatches /api/endpoints/{key}/prune-images.
func (s *Server) handleEndpointRoute(w http.ResponseWriter, r *http.Request) {
	rest := strings.TrimPrefix(r.URL.Path, "/api/endpoints/")
	parts := strings.Split(rest, "/")
	if len(parts) != 2 || parts[0] == "" || parts[1] != "prune-images" {
		http.NotFound(w, r)
		return
	}
	if r.Method != http.MethodPost {
		w.Header().Set("Allow", http.MethodPost)
		writeJSON(w, http.StatusMethodNotAllowed, map[string]any{"error": "method not allowed"})
		return
	}
	if !s.authorizeEndpointAdmin(w, r) {
		return
	}
	s.handlePruneImages(w, r, parts[0])
}

func (s *Server) handlePruneImages(w http.ResponseWriter, r *http.Request, key string) {
	endpoint, ok := s.managedEndpoint(key)
	if !ok {
		s.auditEndpointAttempt(r, ManagedEndpoint{Key: key}, "refused: unknown endpoint")
		writeJSON(w, http.StatusNotFound, map[string]any{
			"error":   "unknown endpoint",
			"message": fmt.Sprintf("no managed endpoint named %q", key),
		})
		return
	}

	allImages, err := boolQueryParameter(r, "all")
	if err != nil {
		s.auditEndpointAttempt(r, endpoint, "refused: "+err.Error())
		writeJSON(w, http.StatusBadRequest, map[string]any{"error": err.Error()})
		return
	}

	result, err := s.pruneEndpointImages(r.Context(), endpoint, allImages)
	if err != nil {
		status := http.StatusBadGateway
		var configErr *endpointConfigError
		if errors.As(err, &configErr) {
			status = http.StatusServiceUnavailable
		}
		s.auditEndpointAttempt(r, endpoint, endpointFailureOutcome(err))
		writeJSON(w, status, map[string]any{"error": err.Error()})
		return
	}
	s.auditEndpointAttempt(r, endpoint, fmt.Sprintf("deleted %d images, reclaimed %d bytes", result.DeletedCount, result.SpaceReclaimedBytes))
	writeJSON(w, http.StatusOK, result)
}

func (s *Server) managedEndpoint(key string) (ManagedEndpoint, bool) {
	for _, endpoint := range s.cfg.Endpoints {
		if endpoint.Key == key {
			return endpoint, true
		}
	}
	return ManagedEndpoint{}, false
}

// auditEndpointAttempt writes exactly one line for each attempt on a destructive
// endpoint-management route, including refusals. It records the principal
// identity (email or client id), never the credential itself, and deliberately
// omits request bodies, headers and the Portainer API key.
func (s *Server) auditEndpointAttempt(r *http.Request, endpoint ManagedEndpoint, outcome string) {
	principal, _ := PrincipalFromContext(r.Context())
	method := principal.Method
	if method == "" {
		method = "anonymous"
	}
	log.Printf("archview endpoints: prune-images endpoint=%q portainerEndpointId=%d principal=%q method=%q mode=%q outcome=%q",
		endpoint.Key, endpoint.PortainerEndpointID, endpointPrincipalIdentity(principal), method, pruneMode(r), outcome)
}

// endpointPrincipalIdentity names the caller without exposing the token.
func endpointPrincipalIdentity(principal Principal) string {
	if principal.Email != "" {
		return principal.Email
	}
	if principal.Method == "client_credentials" {
		if principal.Name != "" {
			return principal.Name
		}
		return principal.Subject
	}
	if principal.Name != "" {
		return principal.Name
	}
	if principal.Subject != "" {
		return principal.Subject
	}
	return "anonymous"
}

// pruneMode reports the requested mode without validating the parameter, so
// refusals can be audited even when the request is malformed.
func pruneMode(r *http.Request) string {
	switch strings.ToLower(strings.TrimSpace(r.URL.Query().Get("all"))) {
	case "1", "true", "yes", "on":
		return "all"
	default:
		return "dangling"
	}
}

func endpointFailureOutcome(err error) string {
	var statusErr *portainerStatusError
	if errors.As(err, &statusErr) {
		return fmt.Sprintf("failed: upstream status %d", statusErr.statusCode)
	}
	return "failed: " + err.Error()
}

// endpointForAudit resolves the endpoint named by the request path, falling
// back to its key so that attempts against unknown endpoints are still logged.
func (s *Server) endpointForAudit(r *http.Request) ManagedEndpoint {
	rest := strings.TrimPrefix(r.URL.Path, "/api/endpoints/")
	key, _, _ := strings.Cut(rest, "/")
	if endpoint, ok := s.managedEndpoint(key); ok {
		return endpoint
	}
	return ManagedEndpoint{Key: key}
}

// authorizeEndpointAdmin enforces the extra authorization required by the
// destructive endpoint-management routes. Authentication itself is still done
// by the shared auth middleware; this only decides whether the authenticated
// caller is an administrator.
//
// Humans are admitted by the email allowlist. Machine callers must both be
// listed in ENDPOINTS_ADMIN_CLIENTS and carry ENDPOINTS_ADMIN_SCOPE in their
// token: a read-only token cannot delete images even if its client id is
// allowlisted.
func (s *Server) authorizeEndpointAdmin(w http.ResponseWriter, r *http.Request) bool {
	refuse := func(status int, code, message string) bool {
		s.auditEndpointAttempt(r, s.endpointForAudit(r), "refused: "+message)
		writeJSON(w, status, map[string]any{
			"error":   code,
			"message": message,
		})
		return false
	}

	if !s.auth.Enabled() {
		// AUTH_MODE=none deliberately leaves the whole API unauthenticated.
		return true
	}

	principal, ok := PrincipalFromContext(r.Context())
	if !ok {
		return refuse(http.StatusUnauthorized, "unauthorized", "authentication required")
	}

	if len(s.cfg.EndpointAdminEmails) == 0 && len(s.cfg.EndpointAdminClients) == 0 {
		return refuse(http.StatusForbidden, "endpoint administration is not configured",
			"set ENDPOINTS_ADMIN_EMAILS or ENDPOINTS_ADMIN_CLIENTS to allow endpoint management")
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
	return refuse(http.StatusForbidden, "forbidden", "this account is not allowed to manage endpoints")
}

type endpointConfigError struct {
	message string
}

func (e *endpointConfigError) Error() string { return e.message }

// portainerStatusError carries the upstream status so the audit line can record
// it without repeating Portainer's response body.
type portainerStatusError struct {
	endpoint   string
	statusCode int
	status     string
	detail     string
}

func (e *portainerStatusError) Error() string {
	if e.detail == "" {
		return fmt.Sprintf("portainer returned %s for endpoint %q", e.status, e.endpoint)
	}
	return fmt.Sprintf("portainer returned %s for endpoint %q: %s", e.status, e.endpoint, e.detail)
}

func (s *Server) pruneEndpointImages(ctx context.Context, endpoint ManagedEndpoint, allImages bool) (PruneImagesResponse, error) {
	if strings.TrimSpace(s.cfg.PortainerURL) == "" {
		return PruneImagesResponse{}, &endpointConfigError{message: "endpoint management is not configured: PORTAINER_URL is not set"}
	}
	if strings.TrimSpace(s.cfg.PortainerAPIKey) == "" {
		return PruneImagesResponse{}, &endpointConfigError{message: "endpoint management is not configured: PORTAINER_API_KEY is not set"}
	}

	filters := map[string][]string{"dangling": {"true"}}
	mode := "dangling"
	if allImages {
		filters["dangling"] = []string{"false"}
		mode = "all"
	}
	filtersJSON, err := json.Marshal(filters)
	if err != nil {
		return PruneImagesResponse{}, err
	}

	target := fmt.Sprintf(
		"%s/api/endpoints/%d/docker/images/prune",
		strings.TrimRight(strings.TrimSpace(s.cfg.PortainerURL), "/"),
		endpoint.PortainerEndpointID,
	)
	parsed, err := url.Parse(target)
	if err != nil {
		return PruneImagesResponse{}, fmt.Errorf("invalid Portainer request URL: %w", err)
	}
	query := parsed.Query()
	query.Set("filters", string(filtersJSON))
	parsed.RawQuery = query.Encode()

	request, err := http.NewRequestWithContext(ctx, http.MethodPost, parsed.String(), nil)
	if err != nil {
		return PruneImagesResponse{}, err
	}
	request.Header.Set("X-API-Key", s.cfg.PortainerAPIKey)
	request.Header.Set("Accept", "application/json")

	response, err := s.portainerClient.Do(request)
	if err != nil {
		return PruneImagesResponse{}, fmt.Errorf("portainer request failed for endpoint %q: %w", endpoint.Key, err)
	}
	defer response.Body.Close()

	body, err := io.ReadAll(io.LimitReader(response.Body, 1<<20))
	if err != nil {
		return PruneImagesResponse{}, fmt.Errorf("read Portainer response for endpoint %q: %w", endpoint.Key, err)
	}
	if response.StatusCode < 200 || response.StatusCode > 299 {
		detail := strings.TrimSpace(string(body))
		if len(detail) > 2048 {
			detail = detail[:2048]
		}
		return PruneImagesResponse{}, &portainerStatusError{
			endpoint:   endpoint.Key,
			statusCode: response.StatusCode,
			status:     response.Status,
			detail:     detail,
		}
	}

	var pruned portainerPruneResponse
	if err := json.Unmarshal(body, &pruned); err != nil {
		return PruneImagesResponse{}, fmt.Errorf("portainer returned an unreadable response for endpoint %q: %w", endpoint.Key, err)
	}

	images := make([]PrunedImage, 0, len(pruned.ImagesDeleted))
	for _, image := range pruned.ImagesDeleted {
		images = append(images, PrunedImage{Deleted: image.Deleted, Untagged: image.Untagged})
	}

	return PruneImagesResponse{
		Endpoint:            endpoint.Key,
		PortainerEndpointID: endpoint.PortainerEndpointID,
		Mode:                mode,
		ImagesDeleted:       images,
		DeletedCount:        len(images),
		SpaceReclaimedBytes: pruned.SpaceReclaimed,
	}, nil
}

func boolQueryParameter(r *http.Request, name string) (bool, error) {
	raw, ok := r.URL.Query()[name]
	if !ok || len(raw) == 0 {
		return false, nil
	}
	switch strings.ToLower(strings.TrimSpace(raw[0])) {
	case "", "0", "false", "no", "off":
		return false, nil
	case "1", "true", "yes", "on":
		return true, nil
	default:
		return false, fmt.Errorf("invalid %s parameter %q: want true or false", name, raw[0])
	}
}
