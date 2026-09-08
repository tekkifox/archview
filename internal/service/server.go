package service

import (
	"context"
	"encoding/json"
	"fmt"
	"html/template"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"syscall"
	"time"
)

type Config struct {
	Addr       string
	DockerAPI  string
	DockerSock string
	HostProc   string
	HostSys    string
	HostRoot   string
}

type Server struct {
	cfg    Config
	client *http.Client
	dash   *template.Template
}

type OverviewResponse struct {
	Title       string          `json:"title"`
	Description string          `json:"description"`
	Status      string          `json:"status"`
	Environment string          `json:"environment"`
	Region      string          `json:"region"`
	Cluster     string          `json:"cluster"`
	UpdatedAt   string          `json:"updatedAt"`
	Services    []ServiceSummary `json:"services"`
	Nodes       []NodeSummary   `json:"nodes"`
	Regions     []string        `json:"regions"`
	Diagram     string          `json:"diagram"`
	Docker      DockerSnapshot   `json:"docker"`
	System      SystemSnapshot   `json:"system"`
	Extra       map[string]any   `json:"extra,omitempty"`
}

type DockerSnapshot struct {
	Daemon     DockerDaemonSummary `json:"daemon"`
	Containers []ContainerSummary  `json:"containers"`
	Images     []ImageSummary      `json:"images"`
}

type DockerDaemonSummary struct {
	ServerVersion     string `json:"serverVersion"`
	ApiVersion        string `json:"apiVersion"`
	OperatingSystem   string `json:"operatingSystem"`
	KernelVersion     string `json:"kernelVersion"`
	Architecture      string `json:"architecture"`
	DockerRootDir     string `json:"dockerRootDir"`
	Driver            string `json:"driver"`
	NCPU              int    `json:"ncpu"`
	MemTotalBytes     int64  `json:"memoryTotalBytes"`
	Containers        int    `json:"containers"`
	ContainersRunning int    `json:"containersRunning"`
	Images            int    `json:"images"`
}

type ContainerSummary struct {
	ID         string            `json:"id"`
	Name       string            `json:"name"`
	Image      string            `json:"image"`
	State      string            `json:"state"`
	Status     string            `json:"status"`
	Created    int64             `json:"created"`
	Ports      []PortSummary     `json:"ports"`
	Labels     map[string]string `json:"labels,omitempty"`
	Command    string            `json:"command,omitempty"`
	MountCount int               `json:"mountCount,omitempty"`
}

type PortSummary struct {
	PrivatePort int    `json:"privatePort"`
	PublicPort  int    `json:"publicPort"`
	Type        string `json:"type"`
	IP          string `json:"ip"`
}

type ImageSummary struct {
	ID           string   `json:"id"`
	RepoTags     []string  `json:"repoTags"`
	SizeBytes    int64     `json:"sizeBytes"`
	Created      int64     `json:"created"`
	Dangling     bool      `json:"dangling"`
	Architecture string   `json:"architecture,omitempty"`
	Os           string    `json:"os,omitempty"`
}

type SystemSnapshot struct {
	Hostname      string            `json:"hostname"`
	OS            string            `json:"os"`
	Kernel        string            `json:"kernel"`
	Architecture  string            `json:"architecture"`
	UptimeSeconds float64           `json:"uptimeSeconds"`
	CPUCount      int               `json:"cpuCount"`
	LoadAverage   []float64        `json:"loadAverage"`
	Memory        MemorySnapshot   `json:"memory"`
	Processes     int               `json:"processes"`
	Disks         []DiskSnapshot    `json:"disks"`
	Network       []NetworkSnapshot `json:"network"`
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
	MountPoint  string  `json:"mountPoint"`
	Filesystem  string  `json:"filesystem"`
	TotalBytes  uint64  `json:"totalBytes"`
	FreeBytes   uint64  `json:"freeBytes"`
	UsedBytes   uint64  `json:"usedBytes"`
	UsedPercent float64 `json:"usedPercent"`
}

type NetworkSnapshot struct {
	Interface string `json:"interface"`
	Received  uint64 `json:"receivedBytes"`
	Sent      uint64 `json:"sentBytes"`
}

type ServiceSummary struct {
	Name   string            `json:"name"`
	Kind   string            `json:"kind"`
	Status string            `json:"status"`
	Image  string            `json:"image,omitempty"`
	Node   string            `json:"node,omitempty"`
	Ports  []PortSummary     `json:"ports,omitempty"`
	Labels map[string]string `json:"labels,omitempty"`
}

type NodeSummary struct {
	Name    string            `json:"name"`
	Kind    string            `json:"kind"`
	Status  string            `json:"status"`
	Details map[string]string `json:"details,omitempty"`
}

type dockerInfo struct {
	ServerVersion     string `json:"ServerVersion"`
	ApiVersion        string `json:"ApiVersion"`
	KernelVersion     string `json:"KernelVersion"`
	OperatingSystem   string `json:"OperatingSystem"`
	Architecture      string `json:"Architecture"`
	DockerRootDir     string `json:"DockerRootDir"`
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
	Command string            `json:"Command"`
	Created int64             `json:"Created"`
	State   string            `json:"State"`
	Status  string            `json:"Status"`
	Labels  map[string]string `json:"Labels"`
	Ports   []dockerPort      `json:"Ports"`
	Mounts  []any             `json:"Mounts"`
}

type dockerPort struct {
	PrivatePort int    `json:"PrivatePort"`
	PublicPort  int    `json:"PublicPort"`
	Type        string `json:"Type"`
	IP          string `json:"IP"`
}

type dockerImage struct {
	ID           string   `json:"Id"`
	RepoTags     []string  `json:"RepoTags"`
	Size         int64     `json:"Size"`
	Created      int64     `json:"Created"`
	Containers   int       `json:"Containers"`
	Dangling     bool      `json:"Dangling"`
	Os           string    `json:"Os"`
	Architecture string    `json:"Architecture"`
}

func NewServer(cfg Config) *Server {
	transport := &http.Transport{
		DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
			return (&net.Dialer{}).DialContext(ctx, "unix", cfg.DockerSock)
		},
	}

	return &Server{
		cfg: cfg,
		client: &http.Client{
			Transport: transport,
			Timeout:   10 * time.Second,
		},
		dash: template.Must(template.New("dashboard").Parse(dashboardTemplate)),
	}
}

func (s *Server) Routes() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("/", s.dashboard)
	mux.HandleFunc("/healthz", s.health)
	mux.HandleFunc("/api/overview", s.handleOverview)
	mux.HandleFunc("/api/architecture", s.handleArchitecture)
	mux.HandleFunc("/api/docker", s.handleDocker)
	mux.HandleFunc("/api/system", s.handleSystem)
	return s.withCORS(mux)
}

func (s *Server) withCORS(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Access-Control-Allow-Origin", "*")
		w.Header().Set("Access-Control-Allow-Headers", "Content-Type, Authorization")
		w.Header().Set("Access-Control-Allow-Methods", "GET, OPTIONS")
		if r.Method == http.MethodOptions {
			w.WriteHeader(http.StatusNoContent)
			return
		}
		next.ServeHTTP(w, r)
	})
}

func (s *Server) dashboard(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path != "/" {
		http.NotFound(w, r)
		return
	}
	data := map[string]any{
		"Title":       "ArchView",
		"Description": "Live Docker and Linux telemetry from the host, served from a separate Go container.",
		"Version":     time.Now().Format(time.RFC3339),
	}
	_ = s.dash.Execute(w, data)
}

func (s *Server) health(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, map[string]any{
		"status": "ok",
		"time":   time.Now().UTC().Format(time.RFC3339),
	})
}

func (s *Server) handleOverview(w http.ResponseWriter, r *http.Request) {
	resp, err := s.buildOverview(r.Context())
	if err != nil {
		writeError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, resp)
}

func (s *Server) handleArchitecture(w http.ResponseWriter, r *http.Request) {
	resp, err := s.buildOverview(r.Context())
	if err != nil {
		writeError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, resp)
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
	docker, err := s.collectDocker(ctx)
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
			Ports:  container.Ports,
			Labels: container.Labels,
		})
	}
	services = append(services, ServiceSummary{
		Name:   "docker-daemon",
		Kind:   "daemon",
		Status: fmt.Sprintf("%d containers, %d images", docker.Daemon.Containers, docker.Daemon.Images),
		Labels: map[string]string{"socket": s.cfg.DockerSock},
	})

	nodes := []NodeSummary{{
		Name:    system.Hostname,
		Kind:    "linux-host",
		Status:  fmt.Sprintf("%0.2f load average", system.LoadAverage[0]),
		Details: map[string]string{"kernel": system.Kernel, "os": system.OS},
	}}
	for _, container := range docker.Containers {
		nodes = append(nodes, NodeSummary{
			Name:   container.Name,
			Kind:   "container",
			Status: container.State,
			Details: map[string]string{"image": container.Image},
		})
	}

	regions := []string{"host", system.OS, docker.Daemon.Architecture}
	diagram := buildDiagram(system, docker)

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
		Diagram:     diagram,
		Docker:      docker,
		System:      system,
		Extra: map[string]any{
			"containerCount": len(docker.Containers),
			"imageCount":     len(docker.Images),
		},
	}, nil
}

func (s *Server) collectDocker(ctx context.Context) (DockerSnapshot, error) {
	info, err := s.requestDocker[dockerInfo](ctx, "/info")
	if err != nil {
		return DockerSnapshot{}, err
	}
	containers, err := s.requestDocker[[]dockerContainer](ctx, "/containers/json?all=1")
	if err != nil {
		return DockerSnapshot{}, err
	}
	images, err := s.requestDocker[[]dockerImage](ctx, "/images/json")
	if err != nil {
		return DockerSnapshot{}, err
	}

	containerSummaries := make([]ContainerSummary, 0, len(containers))
	for _, container := range containers {
		containerSummaries = append(containerSummaries, ContainerSummary{
			ID:      container.ID,
			Name:    cleanDockerName(container.Names),
			Image:   container.Image,
			State:   container.State,
			Status:  container.Status,
			Created: container.Created,
			Ports:   mapPorts(container.Ports),
			Labels:  container.Labels,
			Command: trimCommand(container.Command),
		})
	}

	imageSummaries := make([]ImageSummary, 0, len(images))
	for _, image := range images {
		imageSummaries = append(imageSummaries, ImageSummary{
			ID:           image.ID,
			RepoTags:     image.RepoTags,
			SizeBytes:    image.Size,
			Created:      image.Created,
			Dangling:     image.Dangling,
			Architecture: image.Architecture,
			Os:           image.Os,
		})
	}

	return DockerSnapshot{
		Daemon: DockerDaemonSummary{
			ServerVersion:     info.ServerVersion,
			ApiVersion:        info.ApiVersion,
			OperatingSystem:   info.OperatingSystem,
			KernelVersion:     info.KernelVersion,
			Architecture:      info.Architecture,
			DockerRootDir:     info.DockerRootDir,
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

func (s *Server) collectSystem(ctx context.Context) (SystemSnapshot, error) {
	_ = ctx
	hostname, _ := os.Hostname()
	uptime, _ := readUptime(s.cfg.HostProc)
	load, _ := readLoadAverage(s.cfg.HostProc)
	memory, _ := readMemInfo(s.cfg.HostProc)
	disks, _ := readMountsAndDisks(s.cfg.HostProc, s.cfg.HostRoot)
	network, _ := readNetworkStats(s.cfg.HostProc)
	processes, _ := countProcesses(s.cfg.HostProc)
	kernel, _ := readKernelVersion(s.cfg.HostProc)
	osName, _ := readOSRelease(s.cfg.HostRoot, s.cfg.HostProc)

	return SystemSnapshot{
		Hostname:      hostname,
		OS:            osName,
		Kernel:        kernel,
		Architecture:  runtime.GOARCH,
		UptimeSeconds: uptime,
		CPUCount:      runtime.NumCPU(),
		LoadAverage:   load,
		Memory:        memory,
		Processes:     processes,
		Disks:         disks,
		Network:       network,
	}, nil
}

func (s *Server) requestDocker[T any](ctx context.Context, path string) (T, error) {
	var zero T
	url := fmt.Sprintf("http://docker/%s%s", s.cfg.DockerAPI, path)
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return zero, err
	}
	resp, err := s.client.Do(req)
	if err != nil {
		return zero, err
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 300 {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 2048))
		return zero, fmt.Errorf("docker api %s returned %s: %s", path, resp.Status, strings.TrimSpace(string(body)))
	}
	var parsed T
	if err := json.NewDecoder(resp.Body).Decode(&parsed); err != nil {
		return zero, err
	}
	return parsed, nil
}

func mapPorts(ports []dockerPort) []PortSummary {
	result := make([]PortSummary, 0, len(ports))
	for _, port := range ports {
		result = append(result, PortSummary{
			PrivatePort: port.PrivatePort,
			PublicPort:  port.PublicPort,
			Type:        port.Type,
			IP:          port.IP,
		})
	}
	return result
}

func cleanDockerName(names []string) string {
	if len(names) == 0 {
		return "unnamed"
	}
	return strings.TrimPrefix(names[0], "/")
}

func trimCommand(command string) string {
	command = strings.TrimSpace(command)
	command = strings.TrimPrefix(command, "[")
	command = strings.TrimSuffix(command, "]")
	return strings.ReplaceAll(command, "\"", "")
}

func buildDiagram(system SystemSnapshot, docker DockerSnapshot) string {
	var b strings.Builder
	b.WriteString("host linux system\n")
	b.WriteString("  -> docker daemon\n")
	if len(docker.Containers) == 0 {
		b.WriteString("     -> no containers found\n")
	} else {
		for _, container := range docker.Containers {
			b.WriteString("     -> container: ")
			b.WriteString(container.Name)
			b.WriteString(" (")
			b.WriteString(container.State)
			b.WriteString(")\n")
		}
	}
	b.WriteString("\n")
	b.WriteString(fmt.Sprintf("memory: %0.1f%% used\n", system.Memory.UsedPercent))
	b.WriteString(fmt.Sprintf("load: %0.2f %0.2f %0.2f\n", system.LoadAverage[0], system.LoadAverage[1], system.LoadAverage[2]))
	return b.String()
}

func writeJSON(w http.ResponseWriter, status int, payload any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(status)
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	_ = enc.Encode(payload)
}

func writeError(w http.ResponseWriter, err error) {
	writeJSON(w, http.StatusInternalServerError, map[string]any{"error": err.Error()})
}

func readKernelVersion(procRoot string) (string, error) {
	data, err := os.ReadFile(filepath.Join(procRoot, "version"))
	if err != nil {
		return "", err
	}
	return strings.TrimSpace(string(data)), nil
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

func readUptime(procRoot string) (float64, error) {
	data, err := os.ReadFile(filepath.Join(procRoot, "uptime"))
	if err != nil {
		return 0, err
	}
	fields := strings.Fields(string(data))
	if len(fields) == 0 {
		return 0, fmt.Errorf("uptime data unavailable")
	}
	return strconv.ParseFloat(fields[0], 64)
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
			MountPoint:  mountPoint,
			Filesystem:  fields[0],
			TotalBytes:  stat.total,
			FreeBytes:   stat.free,
			UsedBytes:   stat.used,
			UsedPercent: stat.usedPercent,
		})
		if len(disks) >= 4 {
			break
		}
	}
	return disks, nil
}

type fsStat struct {
	total       uint64
	free        uint64
	used        uint64
	usedPercent float64
}

func statFS(path string) (fsStat, error) {
	var stat syscall.Statfs_t
	if err := syscall.Statfs(path, &stat); err != nil {
		return fsStat{}, err
	}
	total := stat.Blocks * uint64(stat.Bsize)
	free := stat.Bavail * uint64(stat.Bsize)
	used := total - free
	usedPercent := 0.0
	if total > 0 {
		usedPercent = float64(used) / float64(total) * 100
	}
	return fsStat{total: total, free: free, used: used, usedPercent: usedPercent}, nil
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
		iface := strings.TrimSpace(parts[0])
		fields := strings.Fields(strings.TrimSpace(parts[1]))
		if len(fields) < 16 {
			continue
		}
		rx, _ := strconv.ParseUint(fields[0], 10, 64)
		tx, _ := strconv.ParseUint(fields[8], 10, 64)
		stats = append(stats, NetworkSnapshot{Interface: iface, Received: rx, Sent: tx})
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

const dashboardTemplate = `<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>ArchView</title>
  <style>
    :root { color-scheme: dark; --bg: #071018; --card: #0d1b27; --line: rgba(255,255,255,.12); --text: #edf6fb; --muted: #9bb2c5; --accent: #78f4d3; }
    body { margin: 0; font-family: Segoe UI, sans-serif; background: radial-gradient(circle at top, #123249, var(--bg)); color: var(--text); }
    main { width: min(1180px, calc(100vw - 32px)); margin: 0 auto; padding: 28px 0 48px; }
    header, section { background: rgba(255,255,255,.04); border: 1px solid var(--line); border-radius: 22px; padding: 20px; margin-bottom: 18px; backdrop-filter: blur(18px); }
    h1,h2,h3 { font-family: Georgia, serif; margin: 0 0 10px; }
    .grid { display: grid; gap: 18px; grid-template-columns: repeat(2, minmax(0,1fr)); }
    .muted { color: var(--muted); }
    pre { overflow: auto; background: #041018; padding: 14px; border-radius: 16px; border: 1px solid var(--line); }
    table { width: 100%; border-collapse: collapse; }
    th, td { text-align: left; padding: 10px 8px; border-bottom: 1px solid var(--line); vertical-align: top; }
    .tag { display: inline-block; padding: 5px 10px; border-radius: 999px; background: rgba(120,244,211,.12); color: var(--accent); font-size: .8rem; }
    @media (max-width: 860px) { .grid { grid-template-columns: 1fr; } }
  </style>
  <script>
    async function load() {
      const response = await fetch('/api/overview');
      const data = await response.json();
      document.getElementById('status').textContent = data.status;
      document.getElementById('updated').textContent = data.updatedAt;
      document.getElementById('summary').textContent = data.description;
      document.getElementById('system').textContent = JSON.stringify(data.system, null, 2);
      document.getElementById('docker').textContent = JSON.stringify(data.docker, null, 2);
      document.getElementById('diagram').textContent = data.diagram;
      document.getElementById('containers').innerHTML = data.docker.containers.map(function (c) {
        return '<tr><td>' + c.name + '</td><td>' + c.image + '</td><td>' + c.state + '</td><td>' + c.status + '</td></tr>';
      }).join('');
      document.getElementById('images').innerHTML = data.docker.images.map(function (i) {
        var tag = (i.repoTags && i.repoTags[0]) || i.id;
        return '<tr><td>' + tag + '</td><td>' + Math.round(i.sizeBytes / 1024 / 1024) + ' MB</td><td>' + i.created + '</td></tr>';
      }).join('');
    }
    window.addEventListener('DOMContentLoaded', load);
  </script>
</head>
<body>
  <main>
    <header>
      <span class="tag">{{.Title}}</span>
      <h1>{{.Title}}</h1>
      <p class="muted">{{.Description}}</p>
      <p class="muted">Dashboard generated at {{.Version}}</p>
    </header>

    <section>
      <h2>Live overview</h2>
      <p id="summary" class="muted"></p>
      <p>Status: <strong id="status"></strong> | Updated: <span id="updated"></span></p>
      <pre id="diagram"></pre>
    </section>

    <div class="grid">
      <section>
        <h2>System metrics</h2>
        <pre id="system"></pre>
      </section>
      <section>
        <h2>Docker snapshot</h2>
        <pre id="docker"></pre>
      </section>
    </div>

    <section>
      <h2>Containers</h2>
      <table>
        <thead><tr><th>Name</th><th>Image</th><th>State</th><th>Status</th></tr></thead>
        <tbody id="containers"></tbody>
      </table>
    </section>

    <section>
      <h2>Images</h2>
      <table>
        <thead><tr><th>Tag</th><th>Size</th><th>Created</th></tr></thead>
        <tbody id="images"></tbody>
      </table>
    </section>
  </main>
</body>
</html>`package service

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"html/template"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"
)

type Config struct {
	Addr       string
	DockerAPI  string
	DockerSock string
	HostProc   string
	HostSys    string
	HostRoot   string
}

type Server struct {
	cfg      Config
	client   *http.Client
	dash     *template.Template
}

type OverviewResponse struct {
	Title       string            `json:"title"`
	Description string            `json:"description"`
	Status      string            `json:"status"`
	Environment string            `json:"environment"`
	Region      string            `json:"region"`
	Cluster     string            `json:"cluster"`
	UpdatedAt   string            `json:"updatedAt"`
	Services    []ServiceSummary   `json:"services"`
	Nodes       []NodeSummary      `json:"nodes"`
	Regions     []string           `json:"regions"`
	Diagram     string             `json:"diagram"`
	Docker      DockerSnapshot     `json:"docker"`
	System      SystemSnapshot     `json:"system"`
	Extra       map[string]any     `json:"extra,omitempty"`
}

type DockerSnapshot struct {
	Daemon     DockerDaemonSummary `json:"daemon"`
	Containers []ContainerSummary   `json:"containers"`
	Images     []ImageSummary       `json:"images"`
}

type DockerDaemonSummary struct {
	ServerVersion    string `json:"serverVersion"`
	ApiVersion       string `json:"apiVersion"`
	OperatingSystem  string `json:"operatingSystem"`
	KernelVersion    string `json:"kernelVersion"`
	Architecture     string `json:"architecture"`
	DockerRootDir    string `json:"dockerRootDir"`
	Driver           string `json:"driver"`
	NCPU             int    `json:"ncpu"`
	MemTotalBytes    int64  `json:"memoryTotalBytes"`
	Containers       int    `json:"containers"`
	ContainersRunning int   `json:"containersRunning"`
	Images           int    `json:"images"`
}

type ContainerSummary struct {
	ID         string            `json:"id"`
	Name       string            `json:"name"`
	Image      string            `json:"image"`
	State      string            `json:"state"`
	Status     string            `json:"status"`
	Created    int64             `json:"created"`
	Ports      []PortSummary     `json:"ports"`
	Labels     map[string]string `json:"labels,omitempty"`
	Command    string            `json:"command,omitempty"`
	MountCount int               `json:"mountCount,omitempty"`
}

type PortSummary struct {
	PrivatePort int    `json:"privatePort"`
	PublicPort  int    `json:"publicPort"`
	Type        string `json:"type"`
	IP          string `json:"ip"`
}

type ImageSummary struct {
	ID          string   `json:"id"`
	RepoTags    []string  `json:"repoTags"`
	SizeBytes   int64     `json:"sizeBytes"`
	Created     int64     `json:"created"`
	Dangling    bool      `json:"dangling"`
	Architecture string  `json:"architecture,omitempty"`
	Os          string    `json:"os,omitempty"`
}

type SystemSnapshot struct {
	Hostname      string            `json:"hostname"`
	OS            string            `json:"os"`
	Kernel        string            `json:"kernel"`
	Architecture  string            `json:"architecture"`
	UptimeSeconds float64           `json:"uptimeSeconds"`
	CPUCount      int               `json:"cpuCount"`
	LoadAverage   []float64         `json:"loadAverage"`
	Memory       MemorySnapshot     `json:"memory"`
	Processes     int               `json:"processes"`
	Disks        []DiskSnapshot      `json:"disks"`
	Network      []NetworkSnapshot   `json:"network"`
}

type MemorySnapshot struct {
	TotalBytes     int64   `json:"totalBytes"`
	AvailableBytes int64    `json:"availableBytes"`
	FreeBytes      int64    `json:"freeBytes"`
	UsedBytes      int64    `json:"usedBytes"`
	UsedPercent    float64  `json:"usedPercent"`
	SwapTotalBytes int64    `json:"swapTotalBytes"`
	SwapFreeBytes  int64    `json:"swapFreeBytes"`
}

type DiskSnapshot struct {
	MountPoint string  `json:"mountPoint"`
	Filesystem string  `json:"filesystem"`
	TotalBytes uint64  `json:"totalBytes"`
	FreeBytes  uint64  `json:"freeBytes"`
	UsedBytes  uint64  `json:"usedBytes"`
	UsedPercent float64 `json:"usedPercent"`
}

type NetworkSnapshot struct {
	Interface string `json:"interface"`
	Received  uint64 `json:"receivedBytes"`
	Sent      uint64 `json:"sentBytes"`
}

type ServiceSummary struct {
	Name        string            `json:"name"`
	Kind        string            `json:"kind"`
	Status      string            `json:"status"`
	Image       string            `json:"image,omitempty"`
	Node        string            `json:"node,omitempty"`
	Ports       []PortSummary     `json:"ports,omitempty"`
	Labels      map[string]string `json:"labels,omitempty"`
}

type NodeSummary struct {
	Name      string            `json:"name"`
	Kind      string            `json:"kind"`
	Status    string            `json:"status"`
	Details   map[string]string `json:"details,omitempty"`
}

type dockerInfo struct {
	ServerVersion   string `json:"ServerVersion"`
	ApiVersion      string `json:"ApiVersion"`
	KernelVersion   string `json:"KernelVersion"`
	OperatingSystem string `json:"OperatingSystem"`
	Architecture    string `json:"Architecture"`
	DockerRootDir   string `json:"DockerRootDir"`
	Driver          string `json:"Driver"`
	NCPU            int    `json:"NCPU"`
	MemTotal        int64  `json:"MemTotal"`
	Containers      int    `json:"Containers"`
	ContainersRunning int  `json:"ContainersRunning"`
	Images          int    `json:"Images"`
}

type dockerContainer struct {
	ID      string `json:"Id"`
	Names   []string `json:"Names"`
	Image   string `json:"Image"`
	ImageID string `json:"ImageID"`
	Command string `json:"Command"`
	Created int64 `json:"Created"`
	State   string `json:"State"`
	Status  string `json:"Status"`
	Labels  map[string]string `json:"Labels"`
	Ports   []dockerPort `json:"Ports"`
	Mounts  []any `json:"Mounts"`
}

type dockerPort struct {
	PrivatePort int    `json:"PrivatePort"`
	PublicPort  int    `json:"PublicPort"`
	Type        string `json:"Type"`
	IP          string `json:"IP"`
}

type dockerImage struct {
	ID          string   `json:"Id"`
	RepoTags    []string  `json:"RepoTags"`
	Size       int64     `json:"Size"`
	Created    int64     `json:"Created"`
	Containers int       `json:"Containers"`
	Dangling   bool      `json:"Dangling"`
	Os         string    `json:"Os"`
	Architecture string  `json:"Architecture"`
}

func NewServer(cfg Config) *Server {
	transport := &http.Transport{
		DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
			return (&net.Dialer{}).DialContext(ctx, "unix", cfg.DockerSock)
		},
	}

	return &Server{
		cfg: cfg,
		client: &http.Client{
			Transport: transport,
			Timeout:   10 * time.Second,
		},
		dash: template.Must(template.New("dashboard").Parse(dashboardTemplate)),
	}
}

func (s *Server) Routes() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("/", s.dashboard)
	mux.HandleFunc("/healthz", s.health)
	mux.HandleFunc("/api/overview", s.handleOverview)
	mux.HandleFunc("/api/architecture", s.handleArchitecture)
	mux.HandleFunc("/api/docker", s.handleDocker)
	mux.HandleFunc("/api/system", s.handleSystem)
	return s.withCORS(mux)
}

func (s *Server) withCORS(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Access-Control-Allow-Origin", "*")
		w.Header().Set("Access-Control-Allow-Headers", "Content-Type, Authorization")
		w.Header().Set("Access-Control-Allow-Methods", "GET, OPTIONS")
		if r.Method == http.MethodOptions {
			w.WriteHeader(http.StatusNoContent)
			return
		}
		next.ServeHTTP(w, r)
	})
}

func (s *Server) dashboard(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path != "/" {
		http.NotFound(w, r)
		return
	}
	data := map[string]any{
		"Title":       "ArchView",
		"Description": "Live Docker and Linux telemetry from the host, served from a separate Go container.",
		"Version":     time.Now().Format(time.RFC3339),
	}
	_ = s.dash.Execute(w, data)
}

func (s *Server) health(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, map[string]any{
		"status": "ok",
		"time":   time.Now().UTC().Format(time.RFC3339),
	})
}

func (s *Server) handleOverview(w http.ResponseWriter, r *http.Request) {
	resp, err := s.buildOverview(r.Context())
	if err != nil {
		writeError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, resp)
}

func (s *Server) handleArchitecture(w http.ResponseWriter, r *http.Request) {
	resp, err := s.buildOverview(r.Context())
	if err != nil {
		writeError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, resp)
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
	docker, err := s.collectDocker(ctx)
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
			Ports:  container.Ports,
			Labels: container.Labels,
		})
	}
	services = append(services, ServiceSummary{
		Name:   "docker-daemon",
		Kind:   "daemon",
		Status: fmt.Sprintf("%d containers, %d images", docker.Daemon.Containers, docker.Daemon.Images),
		Labels: map[string]string{"socket": s.cfg.DockerSock},
	})

	nodes := []NodeSummary{{
		Name:    system.Hostname,
		Kind:    "linux-host",
		Status:  fmt.Sprintf("%0.2f load average", system.LoadAverage[0]),
		Details: map[string]string{"kernel": system.Kernel, "os": system.OS},
	}}
	for _, container := range docker.Containers {
		nodes = append(nodes, NodeSummary{
			Name:   container.Name,
			Kind:   "container",
			Status: container.State,
			Details: map[string]string{
				"image": container.Image,
			},
		})
	}

	regions := []string{"host", system.OS, docker.Daemon.Architecture}
	diagram := buildDiagram(system, docker)

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
		Diagram:     diagram,
		Docker:      docker,
		System:      system,
		Extra: map[string]any{
			"containerCount": len(docker.Containers),
			"imageCount":     len(docker.Images),
		},
	}, nil
}

func (s *Server) collectDocker(ctx context.Context) (DockerSnapshot, error) {
	info, err := s.requestDocker[ dockerInfo](ctx, "/info")
	if err != nil {
		return DockerSnapshot{}, err
	}
	containers, err := s.requestDocker[[]dockerContainer](ctx, "/containers/json?all=1")
	if err != nil {
		return DockerSnapshot{}, err
	}
	images, err := s.requestDocker[[]dockerImage](ctx, "/images/json")
	if err != nil {
		return DockerSnapshot{}, err
	}

	containerSummaries := make([]ContainerSummary, 0, len(containers))
	for _, container := range containers {
		containerSummaries = append(containerSummaries, ContainerSummary{
			ID:      container.ID,
			Name:    cleanDockerName(container.Names),
			Image:   container.Image,
			State:   container.State,
			Status:  container.Status,
			Created: container.Created,
			Ports:   mapPorts(container.Ports),
			Labels:  container.Labels,
			Command: trimCommand(container.Command),
		})
	}

	imageSummaries := make([]ImageSummary, 0, len(images))
	for _, image := range images {
		imageSummaries = append(imageSummaries, ImageSummary{
			ID:           image.ID,
			RepoTags:     image.RepoTags,
			SizeBytes:    image.Size,
			Created:      image.Created,
			Dangling:     image.Dangling,
			Architecture: image.Architecture,
			Os:           image.Os,
		})
	}

	return DockerSnapshot{
		Daemon: DockerDaemonSummary{
			ServerVersion:    info.ServerVersion,
			ApiVersion:       info.ApiVersion,
			OperatingSystem:  info.OperatingSystem,
			KernelVersion:    info.KernelVersion,
			Architecture:     info.Architecture,
			DockerRootDir:    info.DockerRootDir,
			Driver:           info.Driver,
			NCPU:             info.NCPU,
			MemTotalBytes:    info.MemTotal,
			Containers:       info.Containers,
			ContainersRunning: info.ContainersRunning,
			Images:           info.Images,
		},
		Containers: containerSummaries,
		Images:     imageSummaries,
	}, nil
}

func (s *Server) collectSystem(ctx context.Context) (SystemSnapshot, error) {
	_ = ctx
	hostname, _ := os.Hostname()
	uptime, _ := readUptime(s.cfg.HostProc)
	load, _ := readLoadAverage(s.cfg.HostProc)
	memory, _ := readMemInfo(s.cfg.HostProc)
	disks, _ := readMountsAndDisks(s.cfg.HostProc, s.cfg.HostRoot)
	network, _ := readNetworkStats(s.cfg.HostProc)
	processes, _ := countProcesses(s.cfg.HostProc)
	kernel, _ := readKernelVersion(s.cfg.HostProc)
	osName, _ := readOSRelease(s.cfg.HostRoot, s.cfg.HostProc)
	arch, _ := readMachineArch(s.cfg.HostProc)

	return SystemSnapshot{
		Hostname:      hostname,
		OS:            osName,
		Kernel:        kernel,
		Architecture:  arch,
		UptimeSeconds: uptime,
		CPUCount:      runtimeNumCPU(),
		LoadAverage:   load,
		Memory:        memory,
		Processes:     processes,
		Disks:         disks,
		Network:       network,
	}, nil
}

func (s *Server) requestDocker[T any](ctx context.Context, path string) (T, error) {
	var zero T
	url := fmt.Sprintf("http://docker/%s%s", s.cfg.DockerAPI, path)
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return zero, err
	}
	resp, err := s.client.Do(req)
	if err != nil {
		return zero, err
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 300 {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 2048))
		return zero, fmt.Errorf("docker api %s returned %s: %s", path, resp.Status, strings.TrimSpace(string(body)))
	}
	var parsed T
	if err := json.NewDecoder(resp.Body).Decode(&parsed); err != nil {
		return zero, err
	}
	return parsed, nil
}

func mapPorts(ports []dockerPort) []PortSummary {
	result := make([]PortSummary, 0, len(ports))
	for _, port := range ports {
		result = append(result, PortSummary{
			PrivatePort: port.PrivatePort,
			PublicPort:  port.PublicPort,
			Type:        port.Type,
			IP:          port.IP,
		})
	}
	return result
}

func cleanDockerName(names []string) string {
	if len(names) == 0 {
		return "unnamed"
	}
	return strings.TrimPrefix(names[0], "/")
}

func trimCommand(command string) string {
	command = strings.TrimSpace(command)
	command = strings.TrimPrefix(command, "[")
	command = strings.TrimSuffix(command, "]")
	return strings.ReplaceAll(command, "\"", "")
}

func buildDiagram(system SystemSnapshot, docker DockerSnapshot) string {
	var b strings.Builder
	b.WriteString("host linux system\n")
	b.WriteString("  -> docker daemon\n")
	if len(docker.Containers) == 0 {
		b.WriteString("     -> no containers found\n")
	} else {
		for _, container := range docker.Containers {
			b.WriteString("     -> container: ")
			b.WriteString(container.Name)
			b.WriteString(" (")
			b.WriteString(container.State)
			b.WriteString(")\n")
		}
	}
	b.WriteString("\n")
	b.WriteString(fmt.Sprintf("memory: %0.1f%% used\n", system.Memory.UsedPercent))
	b.WriteString(fmt.Sprintf("load: %0.2f %0.2f %0.2f\n", system.LoadAverage[0], system.LoadAverage[1], system.LoadAverage[2]))
	return b.String()
}

func writeJSON(w http.ResponseWriter, status int, payload any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(status)
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	_ = enc.Encode(payload)
}

func writeError(w http.ResponseWriter, err error) {
	writeJSON(w, http.StatusInternalServerError, map[string]any{
		"error": err.Error(),
	})
}

const dashboardTemplate = `<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>ArchView</title>
  <style>
    :root { color-scheme: dark; --bg: #071018; --card: #0d1b27; --line: rgba(255,255,255,.12); --text: #edf6fb; --muted: #9bb2c5; --accent: #78f4d3; }
    body { margin: 0; font-family: Segoe UI, sans-serif; background: radial-gradient(circle at top, #123249, var(--bg)); color: var(--text); }
    main { width: min(1180px, calc(100vw - 32px)); margin: 0 auto; padding: 28px 0 48px; }
    header, section { background: rgba(255,255,255,.04); border: 1px solid var(--line); border-radius: 22px; padding: 20px; margin-bottom: 18px; backdrop-filter: blur(18px); }
    h1,h2,h3 { font-family: Georgia, serif; margin: 0 0 10px; }
    .grid { display: grid; gap: 18px; grid-template-columns: repeat(2, minmax(0,1fr)); }
    .card { background: var(--card); border: 1px solid var(--line); border-radius: 18px; padding: 16px; }
    .muted { color: var(--muted); }
    pre { overflow: auto; background: #041018; padding: 14px; border-radius: 16px; border: 1px solid var(--line); }
    table { width: 100%; border-collapse: collapse; }
    th, td { text-align: left; padding: 10px 8px; border-bottom: 1px solid var(--line); vertical-align: top; }
    .tag { display: inline-block; padding: 5px 10px; border-radius: 999px; background: rgba(120,244,211,.12); color: var(--accent); font-size: .8rem; }
    @media (max-width: 860px) { .grid { grid-template-columns: 1fr; } }
  </style>
  <script>
    async function load() {
      const response = await fetch('/api/overview');
      const data = await response.json();
      document.getElementById('status').textContent = data.status;
      document.getElementById('updated').textContent = data.updatedAt;
      document.getElementById('summary').textContent = data.description;
      document.getElementById('system').textContent = JSON.stringify(data.system, null, 2);
      document.getElementById('docker').textContent = JSON.stringify(data.docker, null, 2);
      document.getElementById('diagram').textContent = data.diagram;
      const containers = document.getElementById('containers');
      containers.innerHTML = data.docker.containers.map(c => `<tr><td>${c.name}</td><td>${c.image}</td><td>${c.state}</td><td>${c.status}</td></tr>`).join('');
      const images = document.getElementById('images');
      images.innerHTML = data.docker.images.map(i => `<tr><td>${(i.repoTags && i.repoTags[0]) || i.id}</td><td>${Math.round(i.sizeBytes / 1024 / 1024)} MB</td><td>${i.created}</td></tr>`).join('');
    }
    window.addEventListener('DOMContentLoaded', load);
  </script>
</head>
<body>
  <main>
    <header>
      <span class="tag">{{.Title}}</span>
      <h1>{{.Title}}</h1>
      <p class="muted">{{.Description}}</p>
      <p class="muted">Dashboard generated at {{.Version}}</p>
    </header>

    <section>
      <h2>Live overview</h2>
      <p id="summary" class="muted"></p>
      <p>Status: <strong id="status"></strong> | Updated: <span id="updated"></span></p>
      <pre id="diagram"></pre>
    </section>

    <div class="grid">
      <section>
        <h2>System metrics</h2>
        <pre id="system"></pre>
      </section>
      <section>
        <h2>Docker snapshot</h2>
        <pre id="docker"></pre>
      </section>
    </div>

    <section>
      <h2>Containers</h2>
      <table>
        <thead><tr><th>Name</th><th>Image</th><th>State</th><th>Status</th></tr></thead>
        <tbody id="containers"></tbody>
      </table>
    </section>

    <section>
      <h2>Images</h2>
      <table>
        <thead><tr><th>Tag</th><th>Size</th><th>Created</th></tr></thead>
        <tbody id="images"></tbody>
      </table>
    </section>
  </main>
</body>
</html>`

func readText(root, path string) (string, error) {
	if root != "" {
		path = filepath.Join(root, path)
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return "", err
	}
	return string(data), nil
}

func readKernelVersion(procRoot string) (string, error) {
	return strings.TrimSpace(readFirstLine(filepath.Join(procRoot, "version")))
}

func readMachineArch(procRoot string) (string, error) {
	if data, err := os.ReadFile(filepath.Join(procRoot, "cpuinfo")); err == nil {
		text := string(data)
		if strings.Contains(text, "x86_64") {
			return "x86_64", nil
		}
		if strings.Contains(text, "aarch64") {
			return "aarch64", nil
		}
	}
	return runtimeArchitecture(), nil
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

func readUptime(procRoot string) (float64, error) {
	data, err := os.ReadFile(filepath.Join(procRoot, "uptime"))
	if err != nil {
		return 0, err
	}
	fields := strings.Fields(string(data))
	if len(fields) == 0 {
		return 0, fmt.Errorf("uptime data unavailable")
	}
	return strconv.ParseFloat(fields[0], 64)
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
	mounts := []DiskSnapshot{}
	data, err := os.ReadFile(filepath.Join(procRoot, "mounts"))
	if err != nil {
		return mounts, err
	}
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
		var target string
		if root != "" {
			target = filepath.Join(root, strings.TrimPrefix(mountPoint, "/"))
		} else {
			target = mountPoint
		}
		if stat, err := statFS(target); err == nil {
			mounts = append(mounts, DiskSnapshot{
				MountPoint: mountPoint,
				Filesystem: fields[0],
				TotalBytes: stat.total,
				FreeBytes:  stat.free,
				UsedBytes:  stat.used,
				UsedPercent: stat.usedPercent,
			})
		}
		if len(mounts) >= 4 {
			break
		}
	}
	return mounts, nil
}

type fsStat struct {
	total uint64
	free uint64
	used uint64
	usedPercent float64
}

func statFS(path string) (fsStat, error) {
	var stat syscallStatfs
	if err := statfs(path, &stat); err != nil {
		return fsStat{}, err
	}
	total := uint64(stat.Blocks) * uint64(stat.Bsize)
	free := uint64(stat.Bavail) * uint64(stat.Bsize)
	used := total - free
	usedPercent := 0.0
	if total > 0 {
		usedPercent = float64(used) / float64(total) * 100
	}
	return fsStat{total: total, free: free, used: used, usedPercent: usedPercent}, nil
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
	stats := []NetworkSnapshot{}
	for _, line := range strings.Split(string(data), "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "Inter-") || strings.HasPrefix(line, " face") {
			continue
		}
		parts := strings.Split(line, ":")
		if len(parts) != 2 {
			continue
		}
		iface := strings.TrimSpace(parts[0])
		fields := strings.Fields(strings.TrimSpace(parts[1]))
		if len(fields) < 16 {
			continue
		}
		rx, _ := strconv.ParseUint(fields[0], 10, 64)
		tx, _ := strconv.ParseUint(fields[8], 10, 64)
		stats = append(stats, NetworkSnapshot{Interface: iface, Received: rx, Sent: tx})
	}
	return stats, nil
}

func readFirstLine(path string) string {
	data, err := os.ReadFile(path)
	if err != nil {
		return ""
	}
	line, _, _ := strings.Cut(string(data), "\n")
	return strings.TrimSpace(line)
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

func runtimeNumCPU() int { return 1 }
func runtimeArchitecture() string { return "linux" }

type syscallStatfs struct {
	Bsize  int64
	Blocks uint64
	Bavail uint64
}

func statfs(path string, stat *syscallStatfs) error {
	return fmt.Errorf("statfs unavailable on this build target for %s", path)
}