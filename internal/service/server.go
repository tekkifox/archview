package service

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"runtime"
	"strconv"
	"strings"
	"time"

	"github.com/tekkifox/archview/docs"
)

// Config holds the runtime configuration for the ArchView service.
type Config struct {
	Addr       string
	DockerAPI  string
	DockerHost string
	DockerSock string
	HostProc   string
	HostSys    string
	HostRoot   string

	// CORSOrigins lists the exact browser origins (for example
	// "https://dashboard.example.com") allowed to call the API. An empty list
	// disables cross-origin access, leaving the API same-origin only.
	CORSOrigins []string

	// Auth configures OAuth/OIDC login and API authentication.
	Auth AuthConfig
}

type Server struct {
	cfg        Config
	client     *http.Client
	dockerBase string
	auth       *AuthManager
}

type OverviewResponse struct {
	Title       string           `json:"title"`
	Description string           `json:"description"`
	Status      string           `json:"status"`
	Environment string           `json:"environment"`
	Region      string           `json:"region"`
	Cluster     string           `json:"cluster"`
	UpdatedAt   string           `json:"updatedAt"`
	Services    []ServiceSummary `json:"services"`
	Nodes       []NodeSummary    `json:"nodes"`
	Regions     []string         `json:"regions"`
	Docker      DockerSnapshot   `json:"docker"`
	System      SystemSnapshot   `json:"system"`
	Extra       map[string]any   `json:"extra,omitempty"`
	Endpoints   []EndpointLink   `json:"endpoints,omitempty"`
}

// EndpointLink names another API endpoint and gives its absolute URL for the
// instance that served the request.
type EndpointLink struct {
	Name string `json:"name"`
	URL  string `json:"url"`
}

type DockerSnapshot struct {
	Daemon     DockerDaemonSummary `json:"daemon"`
	Containers []ContainerSummary  `json:"containers"`
	Images     []ImageSummary      `json:"images"`
}

type DockerDaemonSummary struct {
	OperatingSystem   string `json:"operatingSystem"`
	Architecture      string `json:"architecture"`
	Driver            string `json:"driver"`
	NCPU              int    `json:"ncpu"`
	MemTotalBytes     int64  `json:"memoryTotalBytes"`
	Containers        int    `json:"containers"`
	ContainersRunning int    `json:"containersRunning"`
	Images            int    `json:"images"`
}

// ContainerSummary deliberately omits ports, labels, commands and mount counts:
// they expose host internals and may carry secrets.
type ContainerSummary struct {
	ID      string `json:"id"`
	Name    string `json:"name"`
	Image   string `json:"image"`
	State   string `json:"state"`
	Status  string `json:"status"`
	Created int64  `json:"created"`
}

type ImageSummary struct {
	RepoTags  []string `json:"repoTags"`
	SizeBytes int64    `json:"sizeBytes"`
	Created   int64    `json:"created"`
	Dangling  bool     `json:"dangling"`
}

type SystemSnapshot struct {
	Hostname    string            `json:"hostname"`
	OS          string            `json:"os"`
	CPUCount    int               `json:"cpuCount"`
	LoadAverage []float64         `json:"loadAverage"`
	Memory      MemorySnapshot    `json:"memory"`
	Processes   int               `json:"processes"`
	Disks       []DiskSnapshot    `json:"disks"`
	Network     []NetworkSnapshot `json:"network"`
}

type MemorySnapshot struct {
	TotalBytes     int64   `json:"totalBytes"`
	AvailableBytes int64   `json:"availableBytes"`
	FreeBytes      int64   `json:"freeBytes"`
	UsedBytes      int64   `json:"usedBytes"`
	UsedPercent    float64 `json:"usedPercent"`
	SwapTotalBytes int64   `json:"swapTotalBytes"`
	SwapFreeBytes  int64   `json:"swapFreeBytes"`
}

type DiskSnapshot struct {
	TotalBytes  uint64  `json:"totalBytes"`
	FreeBytes   uint64  `json:"freeBytes"`
	UsedBytes   uint64  `json:"usedBytes"`
	UsedPercent float64 `json:"usedPercent"`

	// mountPoint identifies the root filesystem for telemetry. It is
	// deliberately unexported so the host path is never serialised.
	mountPoint string
}

type NetworkSnapshot struct {
	Received uint64 `json:"receivedBytes"`
	Sent     uint64 `json:"sentBytes"`
}

type ServiceSummary struct {
	Name   string `json:"name"`
	Kind   string `json:"kind"`
	Status string `json:"status"`
	Image  string `json:"image,omitempty"`
	Node   string `json:"node,omitempty"`
}

type NodeSummary struct {
	Name    string            `json:"name"`
	Kind    string            `json:"kind"`
	Status  string            `json:"status"`
	Details map[string]string `json:"details,omitempty"`
}

type dockerInfo struct {
	OperatingSystem   string `json:"OperatingSystem"`
	Architecture      string `json:"Architecture"`
	Driver            string `json:"Driver"`
	NCPU              int    `json:"NCPU"`
	MemTotal          int64  `json:"MemTotal"`
	Containers        int    `json:"Containers"`
	ContainersRunning int    `json:"ContainersRunning"`
	Images            int    `json:"Images"`
}

type dockerContainer struct {
	ID      string            `json:"Id"`
	Names   []string          `json:"Names"`
	Image   string            `json:"Image"`
	Created int64             `json:"Created"`
	State   string            `json:"State"`
	Status  string            `json:"Status"`
	Labels  map[string]string `json:"Labels"`
}

type dockerImage struct {
	ID       string            `json:"Id"`
	RepoTags []string          `json:"RepoTags"`
	Labels   map[string]string `json:"Labels"`
	Size     int64             `json:"Size"`
	Created  int64             `json:"Created"`
	Dangling bool              `json:"Dangling"`
}

type dockerContainerInspect struct {
	Config struct {
		Labels map[string]string `json:"Labels"`
	} `json:"Config"`
}

// NewServer builds the HTTP server. It validates the authentication
// configuration so that a misconfigured deployment fails at startup instead of
// silently exposing the API.
func NewServer(cfg Config) (*Server, error) {
	dockerBase, transport := dockerTransport(cfg)
	if dockerBase == "" {
		dockerBase = "http://docker"
	}

	auth, err := NewAuthManager(cfg.Auth)
	if err != nil {
		return nil, err
	}

	return &Server{
		cfg:        cfg,
		dockerBase: dockerBase,
		client: &http.Client{
			Transport: transport,
			Timeout:   10 * time.Second,
		},
		auth: auth,
	}, nil
}

func dockerTransport(cfg Config) (string, *http.Transport) {
	if cfg.DockerHost != "" {
		parsed, err := url.Parse(cfg.DockerHost)
		if err == nil {
			baseURL := cfg.DockerHost
			if parsed.Scheme == "tcp" || parsed.Scheme == "http" || parsed.Scheme == "https" {
				baseURL = "http://" + parsed.Host
			}
			return baseURL, &http.Transport{}
		}
	}

	return "http://docker", &http.Transport{
		DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
			return (&net.Dialer{}).DialContext(ctx, "unix", cfg.DockerSock)
		},
	}
}

// Routes returns the fully wired HTTP handler. The API is headless: it only
// serves JSON plus the optional OpenAPI documentation, so it can be embedded in
// any frontend or consumed directly as a microservice.
func (s *Server) Routes() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("/", s.index)
	mux.HandleFunc("/healthz", s.health)
	mux.HandleFunc("/readyz", s.ready)
	mux.HandleFunc("/docs", s.swaggerDocs)
	mux.HandleFunc("/docs/", s.swaggerDocs)
	mux.HandleFunc("/docs/openapi.yaml", s.swaggerSpec)
	mux.HandleFunc("/auth/login", s.auth.HandleLogin)
	mux.HandleFunc("/auth/callback", s.auth.HandleCallback)
	mux.HandleFunc("/auth/logout", s.auth.HandleLogout)
	mux.HandleFunc("/auth/user", s.auth.HandleUser)
	mux.HandleFunc("/auth/config", s.auth.HandleConfig)
	mux.HandleFunc("/api/architecture", s.handleArchitecture)
	mux.HandleFunc("/api/docker", s.handleDocker)
	mux.HandleFunc("/api/system", s.handleSystem)

	var handler http.Handler = mux
	handler = s.auth.Middleware(handler)
	handler = withCORS(s.cfg.CORSOrigins, handler)
	handler = withSecurityHeaders(handler)
	return handler
}

// withCORS only emits CORS headers for explicitly allowed origins. Requests
// from other origins are still served (the browser will block the response),
// which keeps the defaults secure while still allowing multi-origin frontends.
func withCORS(origins []string, next http.Handler) http.Handler {
	allowed := make(map[string]struct{}, len(origins))
	wildcard := false
	for _, origin := range origins {
		origin = strings.TrimRight(strings.TrimSpace(origin), "/")
		if origin == "" {
			continue
		}
		if origin == "*" {
			wildcard = true
			continue
		}
		allowed[origin] = struct{}{}
	}

	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		origin := strings.TrimRight(r.Header.Get("Origin"), "/")
		if origin != "" {
			_, ok := allowed[origin]
			if ok || wildcard {
				if wildcard && !ok {
					w.Header().Set("Access-Control-Allow-Origin", "*")
				} else {
					w.Header().Set("Access-Control-Allow-Origin", origin)
					w.Header().Set("Access-Control-Allow-Credentials", "true")
				}
				w.Header().Add("Vary", "Origin")
				w.Header().Set("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
				w.Header().Set("Access-Control-Allow-Headers", "Authorization, Content-Type, X-Requested-With")
				w.Header().Set("Access-Control-Max-Age", "600")
			}
		}

		if r.Method == http.MethodOptions {
			w.WriteHeader(http.StatusNoContent)
			return
		}
		next.ServeHTTP(w, r)
	})
}

func withSecurityHeaders(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		header := w.Header()
		header.Set("X-Content-Type-Options", "nosniff")
		header.Set("X-Frame-Options", "DENY")
		header.Set("Referrer-Policy", "no-referrer")
		header.Set("Content-Security-Policy", "frame-ancestors 'none'")
		header.Set("Cross-Origin-Opener-Policy", "same-origin")
		if r.TLS != nil {
			header.Set("Strict-Transport-Security", "max-age=31536000; includeSubDomains")
		}
		next.ServeHTTP(w, r)
	})
}

// index describes the service so deployments can discover the API without a
// bundled frontend.
func (s *Server) index(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path != "/" {
		http.NotFound(w, r)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"service":     "archview",
		"description": "Docker daemon and Linux host telemetry API.",
		"version":     "1",
		"auth":        s.auth.PublicInfo(),
		"endpoints": []string{
			"/healthz",
			"/readyz",
			"/docs",
			"/api/architecture?project=<name>",
			"/api/docker",
			"/api/system",
		},
	})
}

func (s *Server) health(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, map[string]any{
		"status": "ok",
		"time":   time.Now().UTC().Format(time.RFC3339),
	})
}

// ready verifies that the service can serve authenticated traffic. Host metric
// collection is best-effort, so a missing Docker socket does not make the pod
// unready; an unreachable identity provider does, because no user could log in.
func (s *Server) ready(w http.ResponseWriter, r *http.Request) {
	ctx, cancel := context.WithTimeout(r.Context(), 5*time.Second)
	defer cancel()

	status := map[string]any{
		"status": "ready",
		"auth":   s.auth.Enabled(),
	}
	code := http.StatusOK
	if err := s.auth.Ready(ctx); err != nil {
		status["status"] = "degraded"
		status["authError"] = err.Error()
		code = http.StatusServiceUnavailable
	}
	writeJSON(w, code, status)
}

func (s *Server) swaggerDocs(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path != "/docs" && r.URL.Path != "/docs/" {
		http.NotFound(w, r)
		return
	}

	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	_, _ = w.Write([]byte(`<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>ArchView API Docs</title>
  <link rel="stylesheet" href="https://unpkg.com/swagger-ui-dist@5/swagger-ui.css">
  <style>body{margin:0;background:#0b1020} .swagger-ui .topbar{display:none}</style>
</head>
<body>
  <div id="swagger-ui"></div>
  <script src="https://unpkg.com/swagger-ui-dist@5/swagger-ui-bundle.js"></script>
  <script>
    window.onload = () => {
      SwaggerUIBundle({
        url: '/docs/openapi.yaml',
        dom_id: '#swagger-ui',
        deepLinking: true,
        presets: [SwaggerUIBundle.presets.apis],
        layout: 'BaseLayout'
      });
    };
  </script>
</body>
</html>`))
}

func (s *Server) swaggerSpec(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/yaml; charset=utf-8")
	_, _ = w.Write(docs.OpenAPISpec)
}

// attachEndpoints records the endpoint links on resp.
func attachEndpoints(resp *OverviewResponse, baseURL string) {
	resp.Endpoints = endpointLinks(baseURL)
}

// endpointLinks lists the API endpoints for the instance at baseURL. URLs are
// absolute so a consumer can follow them without knowing how it reached
// ArchView.
func endpointLinks(baseURL string) []EndpointLink {
	if baseURL == "" {
		return nil
	}
	return []EndpointLink{
		{Name: "architecture", URL: baseURL + "/api/architecture?project=<name>"},
		{Name: "docker", URL: baseURL + "/api/docker"},
		{Name: "system", URL: baseURL + "/api/system"},
		{Name: "healthz", URL: baseURL + "/healthz"},
		{Name: "readyz", URL: baseURL + "/readyz"},
		{Name: "docs", URL: baseURL + "/docs"},
	}
}

// requestBaseURL derives the absolute origin that served r. Forwarded headers
// are honoured only when TRUST_PROXY_HEADERS is enabled, matching the auth
// code's cookie and redirect handling.
func (s *Server) requestBaseURL(r *http.Request) string {
	scheme := "http"
	if r.TLS != nil {
		scheme = "https"
	}
	host := r.Host
	if s.cfg.Auth.TrustProxyHeaders {
		if forwarded := strings.ToLower(firstHeaderValue(r.Header.Get("X-Forwarded-Proto"))); forwarded == "http" || forwarded == "https" {
			scheme = forwarded
		}
		if forwarded := firstHeaderValue(r.Header.Get("X-Forwarded-Host")); forwarded != "" {
			if normalized, ok := normalizeHost(forwarded); ok {
				host = normalized
			}
		}
	}
	normalized, ok := normalizeHost(host)
	if !ok {
		return ""
	}
	return scheme + "://" + normalized
}

// normalizeHost accepts only a bare host with an optional port. It rejects
// schemes, paths, userinfo, queries and fragments so a forwarded header cannot
// change where a link points.
func normalizeHost(raw string) (string, bool) {
	raw = strings.TrimSpace(raw)
	if raw == "" || strings.ContainsAny(raw, "/\\?#@ \t\r\n") {
		return "", false
	}

	host := raw
	port := ""
	if strings.HasPrefix(raw, "[") {
		end := strings.IndexByte(raw, ']')
		if end < 0 {
			return "", false
		}
		host = raw[:end+1]
		rest := raw[end+1:]
		if rest != "" {
			if !strings.HasPrefix(rest, ":") {
				return "", false
			}
			port = rest[1:]
		}
	} else if colons := strings.Count(raw, ":"); colons == 1 {
		idx := strings.IndexByte(raw, ':')
		host, port = raw[:idx], raw[idx+1:]
	} else if colons > 1 {
		// Unbracketed IPv6 literals are not valid in a Host header.
		return "", false
	}

	if host == "" {
		return "", false
	}
	if port != "" {
		number, err := strconv.Atoi(port)
		if err != nil || number < 1 || number > 65535 {
			return "", false
		}
	} else if strings.HasSuffix(raw, ":") {
		return "", false
	}

	if strings.HasPrefix(host, "[") {
		if !strings.HasSuffix(host, "]") || net.ParseIP(host[1:len(host)-1]) == nil {
			return "", false
		}
	} else {
		if strings.HasPrefix(host, ".") || strings.HasSuffix(host, "-") || strings.Contains(host, "..") {
			return "", false
		}
		for _, char := range host {
			if char == '.' || char == '-' || char == '_' ||
				(char >= '0' && char <= '9') ||
				(char >= 'a' && char <= 'z') ||
				(char >= 'A' && char <= 'Z') {
				continue
			}
			return "", false
		}
	}

	if port != "" {
		return strings.ToLower(host) + ":" + port, true
	}
	return strings.ToLower(host), true
}

func (s *Server) handleArchitecture(w http.ResponseWriter, r *http.Request) {
	project := r.URL.Query().Get("project")

	// Require a project query parameter.
	if project == "" {
		writeJSON(w, http.StatusBadRequest, map[string]any{"error": "missing required query parameter: project"})
		return
	}

	// Normalize common aliases
	project = normalizeProject(project)
	baseURL := s.requestBaseURL(r)

	// Determine whether this project should return a full Docker snapshot.
	// Controlled via env FULL_DOCKER_PROJECTS: a comma-separated list of
	// normalised project labels, matched case-sensitively after trimming.
	fullProjectsEnv := os.Getenv("FULL_DOCKER_PROJECTS")
	if fullProjectsEnv != "" {
		for _, p := range strings.Split(fullProjectsEnv, ",") {
			if strings.TrimSpace(p) == project {
				// return full overview for this project
				resp, err := s.buildOverview(r.Context())
				if err != nil {
					writeError(w, err)
					return
				}
				attachEndpoints(&resp, baseURL)
				m, err := attachTelemetryToOverview(resp)
				if err != nil {
					writeJSON(w, http.StatusOK, resp)
					return
				}
				writeJSON(w, http.StatusOK, m)
				return
			}
		}
	}

	// Otherwise return project-scoped overview
	resp, err := s.buildProjectOverview(r.Context(), project)
	if err != nil {
		writeError(w, err)
		return
	}
	attachEndpoints(&resp, baseURL)
	m, err := attachTelemetryToOverview(resp)
	if err != nil {
		writeJSON(w, http.StatusOK, resp)
		return
	}
	writeJSON(w, http.StatusOK, m)
}

// normalizeProject maps the aliases accepted by /api/architecture onto the
// canonical project label. Matching is exact and case-sensitive.
func normalizeProject(project string) string {
	switch project {
	case "travelling", "image-mosaic", "photoprism":
		return "travelling"
	case "rossmoney", "rossmoney-me", "rossmoney_me":
		return "rossmoney_me"
	default:
		return project
	}
}

func (s *Server) handleDocker(w http.ResponseWriter, r *http.Request) {
	docker, err := s.collectDocker(r.Context())
	if err != nil {
		writeError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, docker)
}

func (s *Server) handleSystem(w http.ResponseWriter, r *http.Request) {
	system, err := s.collectSystem(r.Context())
	if err != nil {
		writeError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, system)
}

func (s *Server) buildOverview(ctx context.Context) (OverviewResponse, error) {
	docker, err := s.collectDockerAll(ctx)
	if err != nil {
		return OverviewResponse{}, err
	}
	system, err := s.collectSystem(ctx)
	if err != nil {
		return OverviewResponse{}, err
	}

	services := make([]ServiceSummary, 0, len(docker.Containers)+1)
	for _, container := range docker.Containers {
		services = append(services, ServiceSummary{
			Name:   container.Name,
			Kind:   "container",
			Status: container.Status,
			Image:  container.Image,
		})
	}
	services = append(services, ServiceSummary{
		Name:   "docker-daemon",
		Kind:   "daemon",
		Status: fmt.Sprintf("%d containers, %d images", docker.Daemon.Containers, docker.Daemon.Images),
	})

	nodes := []NodeSummary{{
		Name:   system.Hostname,
		Kind:   "linux-host",
		Status: fmt.Sprintf("%0.2f load average", system.LoadAverage[0]),
	}}
	for _, container := range docker.Containers {
		nodes = append(nodes, NodeSummary{
			Name:   container.Name,
			Kind:   "container",
			Status: container.State,
			Details: map[string]string{
				"image": container.Image,
				"state": container.State,
			},
		})
	}

	regions := []string{"host", system.OS, docker.Daemon.Architecture}

	return OverviewResponse{
		Title:       "Docker + Linux host overview",
		Description: "Separate Go service exposing live Docker daemon, container, image, and Linux host telemetry.",
		Status:      "healthy",
		Environment: "docker",
		Region:      system.OS,
		Cluster:     system.Hostname,
		UpdatedAt:   time.Now().UTC().Format(time.RFC3339),
		Services:    services,
		Nodes:       nodes,
		Regions:     regions,
		Docker:      docker,
		System:      system,
		Extra: map[string]any{
			"containerCount": len(docker.Containers),
			"imageCount":     len(docker.Images),
		},
	}, nil
}

func (s *Server) buildProjectOverview(ctx context.Context, projectLabel string) (OverviewResponse, error) {
	docker, err := s.collectDockerForProject(ctx, projectLabel)
	if err != nil {
		return OverviewResponse{}, err
	}
	system, err := s.collectSystem(ctx)
	if err != nil {
		return OverviewResponse{}, err
	}

	services := make([]ServiceSummary, 0, len(docker.Containers)+1)
	for _, container := range docker.Containers {
		services = append(services, ServiceSummary{
			Name:   container.Name,
			Kind:   "container",
			Status: container.Status,
			Image:  container.Image,
		})
	}
	services = append(services, ServiceSummary{
		Name:   "docker-daemon",
		Kind:   "daemon",
		Status: fmt.Sprintf("%d containers, %d images", docker.Daemon.Containers, docker.Daemon.Images),
	})

	nodes := []NodeSummary{{
		Name:   system.Hostname,
		Kind:   "linux-host",
		Status: fmt.Sprintf("%0.2f load average", system.LoadAverage[0]),
	}}
	for _, container := range docker.Containers {
		nodes = append(nodes, NodeSummary{
			Name:   container.Name,
			Kind:   "container",
			Status: container.State,
			Details: map[string]string{
				"image": container.Image,
				"state": container.State,
			},
		})
	}

	regions := []string{projectLabel, system.OS, docker.Daemon.Architecture}

	return OverviewResponse{
		Title:       "Docker + Linux host overview",
		Description: "Separate Go service exposing live Docker daemon, container, image, and Linux host telemetry.",
		Status:      "healthy",
		Environment: "static",
		Region:      projectLabel,
		Cluster:     system.Hostname,
		UpdatedAt:   time.Now().UTC().Format(time.RFC3339),
		Services:    services,
		Nodes:       nodes,
		Regions:     regions,
		Docker:      docker,
		System:      system,
		Extra: map[string]any{
			"project": projectLabel,
		},
	}, nil
}

func (s *Server) collectDocker(ctx context.Context) (DockerSnapshot, error) {
	var info dockerInfo
	if err := s.requestDocker(ctx, "/info", &info); err != nil {
		return DockerSnapshot{}, err
	}
	projectLabel, _ := s.composeProjectLabel(ctx)
	projectImages := map[string]struct{}{}
	var containers []dockerContainer
	containersPath := "/containers/json"
	if projectLabel != "" {
		filters := map[string][]string{
			"label": {"com.docker.compose.project=" + projectLabel},
		}
		filtersJSON, err := json.Marshal(filters)
		if err != nil {
			return DockerSnapshot{}, err
		}
		containersPath += "?filters=" + url.QueryEscape(string(filtersJSON))
	}
	if err := s.requestDocker(ctx, containersPath, &containers); err != nil {
		return DockerSnapshot{}, err
	}
	var images []dockerImage
	if err := s.requestDocker(ctx, "/images/json", &images); err != nil {
		return DockerSnapshot{}, err
	}

	containerSummaries := make([]ContainerSummary, 0, len(containers))
	for _, container := range containers {
		containerSummaries = append(containerSummaries, ContainerSummary{
			ID:      shortID(container.ID),
			Name:    cleanDockerName(container.Names),
			Image:   container.Image,
			State:   container.State,
			Status:  container.Status,
			Created: container.Created,
		})
		addProjectImage(projectImages, container.Image)
	}

	imageSummaries := make([]ImageSummary, 0, len(images))
	for _, image := range images {
		if !isProjectImage(image, projectImages) {
			continue
		}
		imageSummaries = append(imageSummaries, ImageSummary{
			RepoTags:  image.RepoTags,
			SizeBytes: image.Size,
			Created:   image.Created,
			Dangling:  image.Dangling,
		})
	}

	return DockerSnapshot{
		Daemon: DockerDaemonSummary{
			OperatingSystem:   info.OperatingSystem,
			Architecture:      info.Architecture,
			Driver:            info.Driver,
			NCPU:              info.NCPU,
			MemTotalBytes:     info.MemTotal,
			Containers:        info.Containers,
			ContainersRunning: info.ContainersRunning,
			Images:            info.Images,
		},
		Containers: containerSummaries,
		Images:     imageSummaries,
	}, nil
}

// collectDockerAll collects the full docker snapshot without applying a project filter.
func (s *Server) collectDockerAll(ctx context.Context) (DockerSnapshot, error) {
	var info dockerInfo
	if err := s.requestDocker(ctx, "/info", &info); err != nil {
		return DockerSnapshot{}, err
	}
	containersPath := "/containers/json?all=1"
	var containers []dockerContainer
	if err := s.requestDocker(ctx, containersPath, &containers); err != nil {
		return DockerSnapshot{}, err
	}
	imagesPath := "/images/json?all=1"
	var images []dockerImage
	if err := s.requestDocker(ctx, imagesPath, &images); err != nil {
		return DockerSnapshot{}, err
	}

	containerSummaries := make([]ContainerSummary, 0, len(containers))
	for _, container := range containers {
		// Exclude containers that are in the exited state to avoid showing stale stopped containers
		// in the full overview (e.g., vortexservers full snapshot).
		state := strings.ToLower(strings.TrimSpace(container.State))
		status := strings.ToLower(strings.TrimSpace(container.Status))
		if state == "exited" || strings.Contains(status, "exited") {
			continue
		}

		name := cleanDockerName(container.Names)
		// Exclude anonymous containers whose names are UUIDs or long hex IDs
		if isAnonymousName(name) {
			continue
		}

		containerSummaries = append(containerSummaries, ContainerSummary{
			ID:      shortID(container.ID),
			Name:    name,
			Image:   container.Image,
			State:   container.State,
			Status:  container.Status,
			Created: container.Created,
		})
	}

	imageSummaries := make([]ImageSummary, 0, len(images))
	for _, image := range images {
		// Skip anonymous images that only expose UUID/hex-like repo tags
		if isAnonymousImage(image) {
			continue
		}
		imageSummaries = append(imageSummaries, ImageSummary{
			RepoTags:  image.RepoTags,
			SizeBytes: image.Size,
			Created:   image.Created,
			Dangling:  image.Dangling,
		})
	}

	return DockerSnapshot{
		Daemon: DockerDaemonSummary{
			OperatingSystem:   info.OperatingSystem,
			Architecture:      info.Architecture,
			Driver:            info.Driver,
			NCPU:              info.NCPU,
			MemTotalBytes:     info.MemTotal,
			Containers:        info.Containers,
			ContainersRunning: info.ContainersRunning,
			Images:            info.Images,
		},
		Containers: containerSummaries,
		Images:     imageSummaries,
	}, nil
}

func (s *Server) collectDockerForProject(ctx context.Context, projectLabel string) (DockerSnapshot, error) {
	var info dockerInfo
	if err := s.requestDocker(ctx, "/info", &info); err != nil {
		return DockerSnapshot{}, err
	}
	containersPath := "/containers/json?all=1"
	var containers []dockerContainer
	if err := s.requestDocker(ctx, containersPath, &containers); err != nil {
		return DockerSnapshot{}, err
	}
	imagesPath := "/images/json?all=1"
	var images []dockerImage
	if err := s.requestDocker(ctx, imagesPath, &images); err != nil {
		return DockerSnapshot{}, err
	}

	containerSummaries := make([]ContainerSummary, 0, len(containers))
	for _, container := range containers {
		if projectLabel != "" && !isProjectContainer(container, projectLabel) {
			continue
		}

		name := cleanDockerName(container.Names)
		// Exclude anonymous containers created without a friendly name
		if isAnonymousName(name) {
			continue
		}

		containerSummaries = append(containerSummaries, ContainerSummary{
			ID:      shortID(container.ID),
			Name:    name,
			Image:   container.Image,
			State:   container.State,
			Status:  container.Status,
			Created: container.Created,
		})
	}

	// Build a set of image references used by project containers so we can include all related image tags.
	projectImages := map[string]struct{}{}
	for _, c := range containerSummaries {
		addProjectImage(projectImages, c.Image)
	}

	imageSummaries := make([]ImageSummary, 0, len(images))
	for _, image := range images {
		// Skip anonymous images that only expose UUID/hex-like repo tags
		if isAnonymousImage(image) {
			continue
		}

		// If a project label is supplied, prefer matching images by association with project containers
		// (image IDs, repo tags or normalized refs). This is more reliable than looking for the label in
		// repo tags alone and avoids missing tags that belong to the same repo but don't contain the label.
		if projectLabel != "" {
			if len(projectImages) > 0 {
				if !isProjectImage(image, projectImages) {
					continue
				}
			} else {
				// Fallback: if no container associations were found, fall back to label/tag-based check
				if !isProjectImageForLabel(image, projectLabel) {
					continue
				}
			}
		}

		imageSummaries = append(imageSummaries, ImageSummary{
			RepoTags:  image.RepoTags,
			SizeBytes: image.Size,
			Created:   image.Created,
			Dangling:  image.Dangling,
		})
	}

	return DockerSnapshot{
		Daemon: DockerDaemonSummary{
			OperatingSystem:   info.OperatingSystem,
			Architecture:      info.Architecture,
			Driver:            info.Driver,
			NCPU:              info.NCPU,
			MemTotalBytes:     info.MemTotal,
			Containers:        info.Containers,
			ContainersRunning: info.ContainersRunning,
			Images:            info.Images,
		},
		Containers: containerSummaries,
		Images:     imageSummaries,
	}, nil
}

func addProjectImage(projectImages map[string]struct{}, image string) {
	image = strings.TrimSpace(image)
	if image == "" {
		return
	}
	projectImages[image] = struct{}{}
	projectImages[normalizeImageRef(image)] = struct{}{}
}

func isProjectImage(image dockerImage, projectImages map[string]struct{}) bool {
	if len(projectImages) == 0 {
		return false
	}
	for _, tag := range image.RepoTags {
		tag = strings.TrimSpace(tag)
		if tag == "" {
			continue
		}
		if _, ok := projectImages[tag]; ok {
			return true
		}
		if _, ok := projectImages[normalizeImageRef(tag)]; ok {
			return true
		}
	}
	return false
}

func normalizeImageRef(ref string) string {
	ref = strings.TrimSpace(ref)
	if ref == "" {
		return ""
	}
	if index := strings.Index(ref, "@"); index >= 0 {
		ref = ref[:index]
	}
	lastSlash := strings.LastIndex(ref, "/")
	lastColon := strings.LastIndex(ref, ":")
	if lastColon > lastSlash {
		ref = ref[:lastColon]
	}
	return ref
}

func isProjectContainer(container dockerContainer, projectLabel string) bool {
	if projectLabel == "" {
		return false
	}

	if container.Labels != nil {
		if container.Labels["com.docker.compose.project"] == projectLabel {
			return true
		}
	}

	if strings.Contains(container.Image, projectLabel) {
		return true
	}

	for _, name := range container.Names {
		if strings.Contains(name, projectLabel) {
			return true
		}
	}

	return false
}

func isProjectImageForLabel(image dockerImage, projectLabel string) bool {
	if projectLabel == "" {
		return false
	}

	if image.Labels != nil {
		if image.Labels["com.docker.compose.project"] == projectLabel {
			return true
		}
	}

	for _, tag := range image.RepoTags {
		tag = strings.TrimSpace(tag)
		if tag == "" {
			continue
		}
		if strings.Contains(tag, projectLabel) {
			return true
		}
	}

	return false
}

func (s *Server) composeProjectLabel(ctx context.Context) (string, error) {
	hostname, err := os.Hostname()
	if err != nil || hostname == "" {
		return "", err
	}

	var inspect dockerContainerInspect
	if err := s.requestDocker(ctx, "/containers/"+hostname+"/json", &inspect); err != nil {
		return "", err
	}
	return inspect.Config.Labels["com.docker.compose.project"], nil
}

func (s *Server) collectSystem(ctx context.Context) (SystemSnapshot, error) {
	_ = ctx
	hostname, _ := os.Hostname()
	load, _ := readLoadAverage(s.cfg.HostProc)
	memory, _ := readMemInfo(s.cfg.HostProc)
	disks, _ := readMountsAndDisks(s.cfg.HostProc, s.cfg.HostRoot)
	network, _ := readNetworkStats(s.cfg.HostProc)
	processes, _ := countProcesses(s.cfg.HostProc)
	osName, _ := readOSRelease(s.cfg.HostRoot, s.cfg.HostProc)

	return SystemSnapshot{
		Hostname:    hostname,
		OS:          osName,
		CPUCount:    runtime.NumCPU(),
		LoadAverage: load,
		Memory:      memory,
		Processes:   processes,
		Disks:       disks,
		Network:     network,
	}, nil
}

func (s *Server) requestDocker(ctx context.Context, path string, out any) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, fmt.Sprintf("%s/%s%s", strings.TrimRight(s.dockerBase, "/"), s.cfg.DockerAPI, path), nil)
	if err != nil {
		return err
	}
	resp, err := s.client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 300 {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 2048))
		return fmt.Errorf("docker api %s returned %s: %s", path, resp.Status, strings.TrimSpace(string(body)))
	}
	return json.NewDecoder(resp.Body).Decode(out)
}

func shortID(id string) string {
	if len(id) > 12 {
		return id[:12]
	}
	return id
}

func cleanDockerName(names []string) string {
	if len(names) == 0 {
		return "unnamed"
	}
	return strings.TrimPrefix(names[0], "/")
}

// isAnonymousName returns true when the container name looks like an auto-generated
// anonymous name (a long hex string or a UUID). These are often short-lived or
// unhelpful for topology views and can be excluded from dashboards.
func isAnonymousName(name string) bool {
	n := strings.TrimSpace(name)
	if n == "" {
		return true
	}
	// canonical UUID form (case-insensitive) or UUID-like substring
	uuidHyphenFull := regexp.MustCompile(`(?i)^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$`)
	uuidHyphenAny := regexp.MustCompile(`(?i)[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}`)
	if uuidHyphenFull.MatchString(n) || uuidHyphenAny.FindString(n) != "" {
		return true
	}
	// long hex (Docker sometimes uses short IDs; treat long runs of hex as anonymous)
	hexLong := regexp.MustCompile(`(?i)^[0-9a-f]{12,}$`)
	if hexLong.MatchString(n) {
		return true
	}
	return false
}

// isAnonymousImage returns true when all repo tags for an image look like
// auto-generated identifiers (UUIDs or long hex). These images are not useful
// for topology overviews and can be omitted.
func isAnonymousImage(image dockerImage) bool {
	// If there are no repo tags, consider the image anonymous
	if len(image.RepoTags) == 0 {
		return true
	}
	uuidHyphen := regexp.MustCompile(`^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$`)
	hexLong := regexp.MustCompile(`^[0-9a-f]{12,}$`)
	sha256Re := regexp.MustCompile(`(?i)sha256:[0-9a-f]{64}`)
	allAnonymous := true
	for _, tag := range image.RepoTags {
		t := strings.TrimSpace(strings.ToLower(tag))
		if t == "<none>:<none>" || t == "<none>" || t == "" {
			continue
		}
		// treat digest-only tags like sha256:... as anonymous
		if sha256Re.MatchString(t) {
			continue
		}
		if uuidHyphen.MatchString(t) || hexLong.MatchString(t) {
			continue
		}
		// if any tag looks human-readable, it's not anonymous
		allAnonymous = false
		break
	}
	// Also treat images with ID that are digests (sha256:...) as anonymous
	if allAnonymous {
		id := strings.TrimSpace(strings.ToLower(image.ID))
		if id != "" && sha256Re.MatchString(id) {
			return true
		}
	}
	return allAnonymous
}

func writeJSON(w http.ResponseWriter, status int, payload any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(status)
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	_ = enc.Encode(payload)
}

func writeError(w http.ResponseWriter, err error) {
	log.Printf("archview: request failed: %v", err)
	writeJSON(w, http.StatusInternalServerError, map[string]any{"error": "internal server error"})
}

func readOSRelease(root, procRoot string) (string, error) {
	paths := []string{
		filepath.Join(root, "etc", "os-release"),
		filepath.Join(procRoot, "os-release"),
		"/etc/os-release",
	}
	for _, path := range paths {
		data, err := os.ReadFile(path)
		if err != nil {
			continue
		}
		for _, line := range strings.Split(string(data), "\n") {
			if strings.HasPrefix(line, "PRETTY_NAME=") {
				return strings.Trim(strings.TrimPrefix(line, "PRETTY_NAME="), `"`), nil
			}
		}
	}
	return "Linux", nil
}

func readLoadAverage(procRoot string) ([]float64, error) {
	data, err := os.ReadFile(filepath.Join(procRoot, "loadavg"))
	if err != nil {
		return []float64{0, 0, 0}, err
	}
	fields := strings.Fields(string(data))
	load := []float64{0, 0, 0}
	for i := 0; i < 3 && i < len(fields); i++ {
		value, _ := strconv.ParseFloat(fields[i], 64)
		load[i] = value
	}
	return load, nil
}

func readMemInfo(procRoot string) (MemorySnapshot, error) {
	data, err := os.ReadFile(filepath.Join(procRoot, "meminfo"))
	if err != nil {
		return MemorySnapshot{}, err
	}
	info := map[string]int64{}
	for _, line := range strings.Split(string(data), "\n") {
		fields := strings.Fields(line)
		if len(fields) < 2 {
			continue
		}
		key := strings.TrimSuffix(fields[0], ":")
		value, err := strconv.ParseInt(fields[1], 10, 64)
		if err != nil {
			continue
		}
		info[key] = value * 1024
	}
	total := info["MemTotal"]
	available := info["MemAvailable"]
	free := info["MemFree"]
	used := total - available
	if available == 0 {
		available = free
		used = total - free
	}
	usedPercent := 0.0
	if total > 0 {
		usedPercent = float64(used) / float64(total) * 100
	}
	return MemorySnapshot{
		TotalBytes:     total,
		AvailableBytes: available,
		FreeBytes:      free,
		UsedBytes:      used,
		UsedPercent:    usedPercent,
		SwapTotalBytes: info["SwapTotal"],
		SwapFreeBytes:  info["SwapFree"],
	}, nil
}

func readMountsAndDisks(procRoot, root string) ([]DiskSnapshot, error) {
	data, err := os.ReadFile(filepath.Join(procRoot, "mounts"))
	if err != nil {
		return nil, err
	}
	var disks []DiskSnapshot
	seen := map[string]bool{}
	for _, line := range strings.Split(string(data), "\n") {
		fields := strings.Fields(line)
		if len(fields) < 3 {
			continue
		}
		mountPoint := fields[1]
		if seen[mountPoint] || !strings.HasPrefix(mountPoint, "/") {
			continue
		}
		seen[mountPoint] = true
		if strings.HasPrefix(mountPoint, "/proc") || strings.HasPrefix(mountPoint, "/sys") || strings.HasPrefix(mountPoint, "/dev") {
			continue
		}
		target := mountPoint
		if root != "" {
			target = filepath.Join(root, strings.TrimPrefix(mountPoint, "/"))
		}
		stat, err := statFS(target)
		if err != nil {
			continue
		}
		disks = append(disks, DiskSnapshot{
			TotalBytes:  stat.total,
			FreeBytes:   stat.free,
			UsedBytes:   stat.used,
			UsedPercent: stat.usedPercent,
			mountPoint:  mountPoint,
		})
		if len(disks) >= 4 {
			break
		}
	}
	return disks, nil
}

func countProcesses(procRoot string) (int, error) {
	entries, err := os.ReadDir(procRoot)
	if err != nil {
		return 0, err
	}
	count := 0
	for _, entry := range entries {
		if entry.IsDir() && isDigits(entry.Name()) {
			count++
		}
	}
	return count, nil
}

func readNetworkStats(procRoot string) ([]NetworkSnapshot, error) {
	data, err := os.ReadFile(filepath.Join(procRoot, "net", "dev"))
	if err != nil {
		return nil, err
	}
	var stats []NetworkSnapshot
	for _, line := range strings.Split(string(data), "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "Inter-") || strings.HasPrefix(line, "face") {
			continue
		}
		parts := strings.Split(line, ":")
		if len(parts) != 2 {
			continue
		}
		fields := strings.Fields(strings.TrimSpace(parts[1]))
		if len(fields) < 16 {
			continue
		}
		rx, _ := strconv.ParseUint(fields[0], 10, 64)
		tx, _ := strconv.ParseUint(fields[8], 10, 64)
		stats = append(stats, NetworkSnapshot{Received: rx, Sent: tx})
	}
	return stats, nil
}

func isDigits(value string) bool {
	if value == "" {
		return false
	}
	for _, r := range value {
		if r < '0' || r > '9' {
			return false
		}
	}
	return true
}
