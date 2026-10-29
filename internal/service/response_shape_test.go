package service

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

const shortContainerID = "0123456789ab"

func responseShapeDockerServer(t *testing.T) *httptest.Server {
	t.Helper()

	fullContainerID := shortContainerID + "cdef0123456789abcdef0123456789abcdef0123456789abcdef01"
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		switch {
		case strings.HasSuffix(r.URL.Path, "/info"):
			_, _ = w.Write([]byte(`{
				"ServerVersion":"27.0.0",
				"ApiVersion":"1.46",
				"OperatingSystem":"Debian GNU/Linux 12",
				"KernelVersion":"6.8.0-secret",
				"Architecture":"x86_64",
				"DockerRootDir":"/var/lib/docker",
				"Driver":"overlay2",
				"NCPU":8,
				"MemTotal":16000000000,
				"Containers":3,
				"ContainersRunning":2,
				"Images":5
			}`))
		case strings.HasSuffix(r.URL.Path, "/containers/json"):
			_, _ = w.Write([]byte(`[{
				"Id":"` + fullContainerID + `",
				"Names":["/demo-app"],
				"Image":"demo/app:latest",
				"Command":"/bin/sh -c printf supersecret",
				"Created":1700000000,
				"State":"running",
				"Status":"Up 2 hours",
				"Labels":{"com.docker.compose.project":"demo","traefik.http.routers.demo.rule":"Host(secret.example.com)"},
				"Ports":[{"PrivatePort":80,"PublicPort":8080,"Type":"tcp","IP":"127.0.0.1"}],
				"Mounts":[{"Source":"/srv/secret","Destination":"/data"}]
			}]`))
		case strings.HasSuffix(r.URL.Path, "/images/json"):
			_, _ = w.Write([]byte(`[{
				"Id":"sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
				"RepoTags":["demo/app:latest"],
				"Labels":{"com.docker.compose.project":"demo"},
				"Size":123456789,
				"Created":1690000000,
				"Containers":2,
				"Dangling":false,
				"Architecture":"amd64",
				"Os":"linux"
			}]`))
		case strings.Contains(r.URL.Path, "/containers/") && strings.HasSuffix(r.URL.Path, "/json"):
			_, _ = w.Write([]byte(`{"Config":{"Labels":{"com.docker.compose.project":"demo"}}}`))
		default:
			http.NotFound(w, r)
		}
	}))
	t.Cleanup(server.Close)
	return server
}

func newResponseShapeServer(t *testing.T) *Server {
	t.Helper()

	hostRoot := t.TempDir()
	writeFixture := func(name, content string) {
		t.Helper()
		if err := os.WriteFile(filepath.Join(hostRoot, name), []byte(content), 0o600); err != nil {
			t.Fatalf("write host fixture %s: %v", name, err)
		}
	}
	writeFixture("loadavg", "0.50 0.40 0.30 1/100 12345\n")
	writeFixture("meminfo", "MemTotal: 1000 kB\nMemFree: 200 kB\nMemAvailable: 400 kB\nSwapTotal: 100 kB\nSwapFree: 50 kB\n")
	writeFixture("mounts", "overlay / overlay rw 0 0\n")
	if err := os.MkdirAll(filepath.Join(hostRoot, "net"), 0o700); err != nil {
		t.Fatalf("create net fixture: %v", err)
	}
	writeFixture(filepath.Join("net", "dev"), "Inter-|   Receive                                                |  Transmit\n face |bytes    packets errs drop fifo frame compressed multicast|bytes    packets errs drop fifo colls carrier compressed\n    lo: 1024 10 0 0 0 0 0 0 2048 20 0 0 0 0 0 0\n")

	server, err := NewServer(Config{
		DockerHost: responseShapeDockerServer(t).URL,
		HostProc:   hostRoot,
		HostRoot:   hostRoot,
		Auth:       AuthConfig{Mode: authModeNone},
	})
	if err != nil {
		t.Fatalf("NewServer: %v", err)
	}
	return server
}

func getJSON(t *testing.T, handler http.Handler, target string) []byte {
	t.Helper()

	request := httptest.NewRequest(http.MethodGet, "https://archview.example"+target, nil)
	recorder := httptest.NewRecorder()
	handler.ServeHTTP(recorder, request)
	if recorder.Code != http.StatusOK {
		t.Fatalf("GET %s status = %d, want 200 (body %s)", target, recorder.Code, recorder.Body.String())
	}
	return recorder.Body.Bytes()
}

func TestDockerResponseOmitsSensitiveFields(t *testing.T) {
	handler := newResponseShapeServer(t).Routes()
	body := string(getJSON(t, handler, "/api/docker"))

	for _, forbidden := range []string{
		"ports",
		"command",
		"labels",
		"mountCount",
		"kernel",
		"kernelVersion",
		"dockerRootDir",
		"apiVersion",
		"serverVersion",
		"uptimeSeconds",
		"mountPoint",
		"filesystem",
		"interface",
	} {
		if strings.Contains(body, `"`+forbidden+`"`) {
			t.Errorf("docker response still contains removed field %q: %s", forbidden, body)
		}
	}

	for _, retained := range []string{
		"operatingSystem",
		"architecture",
		"driver",
		"ncpu",
		"memoryTotalBytes",
		"containers",
		"containersRunning",
		"images",
		"id",
		"name",
		"image",
		"state",
		"status",
		"created",
		"repoTags",
		"sizeBytes",
		"dangling",
	} {
		if !strings.Contains(body, `"`+retained+`"`) {
			t.Errorf("docker response lost retained field %q: %s", retained, body)
		}
	}
}

func TestDockerResponseUsesShortContainerID(t *testing.T) {
	handler := newResponseShapeServer(t).Routes()

	var snapshot DockerSnapshot
	if err := json.Unmarshal(getJSON(t, handler, "/api/docker"), &snapshot); err != nil {
		t.Fatalf("decode docker response: %v", err)
	}
	if len(snapshot.Containers) != 1 {
		t.Fatalf("got %d containers, want 1", len(snapshot.Containers))
	}
	if got := snapshot.Containers[0].ID; got != shortContainerID {
		t.Fatalf("container ID = %q, want %q", got, shortContainerID)
	}
	if len(snapshot.Images) != 1 {
		t.Fatalf("got %d images, want 1", len(snapshot.Images))
	}
	if got := snapshot.Images[0].RepoTags; len(got) != 1 || got[0] != "demo/app:latest" {
		t.Fatalf("image repo tags = %v, want [demo/app:latest]", got)
	}
}

func TestOverviewResponseOmitsSensitiveFields(t *testing.T) {
	handler := newResponseShapeServer(t).Routes()
	body := string(getJSON(t, handler, "/api/overview"))

	for _, forbidden := range []string{
		"ports",
		"command",
		"labels",
		"mountCount",
		"kernel",
		"kernelVersion",
		"dockerRootDir",
		"apiVersion",
		"serverVersion",
		"uptimeSeconds",
		"mountPoint",
		"filesystem",
		"interface",
	} {
		if strings.Contains(body, `"`+forbidden+`"`) {
			t.Errorf("overview response still contains removed field %q: %s", forbidden, body)
		}
	}

	for _, retained := range []string{
		"hostname",
		"os",
		"cpuCount",
		"loadAverage",
		"memory",
		"processes",
		"disks",
		"network",
		"totalBytes",
		"freeBytes",
		"usedBytes",
		"usedPercent",
		"receivedBytes",
		"sentBytes",
		"diagram",
		"endpoints",
		"services",
		"nodes",
		"regions",
	} {
		if !strings.Contains(body, `"`+retained+`"`) {
			t.Errorf("overview response lost retained field %q: %s", retained, body)
		}
	}

	var response OverviewResponse
	if err := json.Unmarshal([]byte(body), &response); err != nil {
		t.Fatalf("decode overview response: %v", err)
	}
	for _, node := range response.Nodes {
		if node.Kind != "container" {
			continue
		}
		if node.Details["image"] != "demo/app:latest" {
			t.Fatalf("container node image = %q, want demo/app:latest", node.Details["image"])
		}
		if node.Details["state"] != "running" {
			t.Fatalf("container node state = %q, want running", node.Details["state"])
		}
	}
}

func TestArchitectureResponseOmitsKernelFromTelemetry(t *testing.T) {
	handler := newResponseShapeServer(t).Routes()
	body := string(getJSON(t, handler, "/api/architecture?project=demo"))

	for _, forbidden := range []string{"kernel", "mountPoint", "filesystem", "interface", "uptimeSeconds"} {
		if strings.Contains(body, `"`+forbidden+`"`) {
			t.Errorf("architecture response still contains removed field %q: %s", forbidden, body)
		}
	}
	for _, retained := range []string{"telemetry", "hosts", "metrics", "diagram", "endpoints"} {
		if !strings.Contains(body, `"`+retained+`"`) {
			t.Errorf("architecture response lost retained field %q: %s", retained, body)
		}
	}
}
