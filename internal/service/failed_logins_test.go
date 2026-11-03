package service

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
)

func writeFailedLoginsFixture(t *testing.T, hostRoot, content string) {
	t.Helper()

	dir := filepath.Join(hostRoot, "var", "lib")
	if err := os.MkdirAll(dir, 0o700); err != nil {
		t.Fatalf("create failed-logins fixture dir: %v", err)
	}
	if err := os.WriteFile(filepath.Join(dir, "ssh-failed-logins.txt"), []byte(content), 0o600); err != nil {
		t.Fatalf("write failed-logins fixture: %v", err)
	}
}

func TestReadFailedLoginsParsesInteger(t *testing.T) {
	hostRoot := t.TempDir()
	writeFailedLoginsFixture(t, hostRoot, "7\n")

	got := readFailedLogins(hostRoot)
	if got == nil {
		t.Fatal("readFailedLogins = nil, want 7")
	}
	if *got != 7 {
		t.Fatalf("readFailedLogins = %d, want 7", *got)
	}
}

func TestReadFailedLoginsUnavailableIsNil(t *testing.T) {
	hostRoot := t.TempDir()
	writeFailedLoginsFixture(t, hostRoot, "unavailable\n")

	if got := readFailedLogins(hostRoot); got != nil {
		t.Fatalf("readFailedLogins = %d, want nil for unavailable", *got)
	}
}

func TestReadFailedLoginsMissingFileIsNil(t *testing.T) {
	if got := readFailedLogins(t.TempDir()); got != nil {
		t.Fatalf("readFailedLogins = %d, want nil for a missing file", *got)
	}
}

func TestReadFailedLoginsEmptyRootIsNil(t *testing.T) {
	if got := readFailedLogins(""); got != nil {
		t.Fatalf("readFailedLogins = %d, want nil when HOST_ROOT is empty", *got)
	}
}

func TestReadFailedLoginsInvalidContentIsNil(t *testing.T) {
	hostRoot := t.TempDir()
	writeFailedLoginsFixture(t, hostRoot, "not-a-count\n")

	if got := readFailedLogins(hostRoot); got != nil {
		t.Fatalf("readFailedLogins = %d, want nil for invalid content", *got)
	}
}

func TestSystemEndpointReportsFailedLogins(t *testing.T) {
	hostRoot := t.TempDir()
	writeFailedLoginsFixture(t, hostRoot, "42\n")

	server, err := NewServer(Config{
		HostProc: t.TempDir(),
		HostRoot: hostRoot,
		Auth:     AuthConfig{Mode: authModeNone},
	})
	if err != nil {
		t.Fatalf("NewServer: %v", err)
	}

	request := httptest.NewRequest(http.MethodGet, "https://archview.example/api/system", nil)
	recorder := httptest.NewRecorder()
	server.Routes().ServeHTTP(recorder, request)
	if recorder.Code != http.StatusOK {
		t.Fatalf("GET /api/system status = %d, want 200 (body %s)", recorder.Code, recorder.Body.String())
	}

	var payload struct {
		FailedLogins       *int   `json:"failedLogins"`
		FailedLoginsWindow string `json:"failedLoginsWindow"`
	}
	if err := json.Unmarshal(recorder.Body.Bytes(), &payload); err != nil {
		t.Fatalf("decode system response: %v", err)
	}
	if payload.FailedLogins == nil || *payload.FailedLogins != 42 {
		t.Fatalf("failedLogins = %v, want 42 (body %s)", payload.FailedLogins, recorder.Body.String())
	}
	if payload.FailedLoginsWindow != failedLoginsWindow {
		t.Fatalf("failedLoginsWindow = %q, want %q", payload.FailedLoginsWindow, failedLoginsWindow)
	}
}

func TestSystemEndpointKeepsFailedLoginsNullWhenMissing(t *testing.T) {
	server, err := NewServer(Config{
		HostProc: t.TempDir(),
		HostRoot: t.TempDir(),
		Auth:     AuthConfig{Mode: authModeNone},
	})
	if err != nil {
		t.Fatalf("NewServer: %v", err)
	}

	request := httptest.NewRequest(http.MethodGet, "https://archview.example/api/system", nil)
	recorder := httptest.NewRecorder()
	server.Routes().ServeHTTP(recorder, request)
	if recorder.Code != http.StatusOK {
		t.Fatalf("GET /api/system status = %d, want 200 (body %s)", recorder.Code, recorder.Body.String())
	}

	var fields map[string]json.RawMessage
	if err := json.Unmarshal(recorder.Body.Bytes(), &fields); err != nil {
		t.Fatalf("decode system response: %v", err)
	}
	raw, ok := fields["failedLogins"]
	if !ok {
		t.Fatalf("system response is missing failedLogins: %s", recorder.Body.String())
	}
	if string(raw) != "null" {
		t.Fatalf("failedLogins = %s, want null when the file is missing", raw)
	}
	if raw, ok := fields["failedLoginsWindow"]; !ok || string(raw) != `"1h"` {
		t.Fatalf("failedLoginsWindow = %s (present %v), want \"1h\"", raw, ok)
	}
}

func TestTelemetryIncludesFailedLogins(t *testing.T) {
	count := 3
	telemetry := processOverviewTelemetry(OverviewResponse{
		System: SystemSnapshot{
			Hostname:           "host1.example.com",
			FailedLogins:       &count,
			FailedLoginsWindow: failedLoginsWindow,
		},
	})

	hosts, _ := telemetry["hosts"].([]map[string]any)
	if len(hosts) != 1 {
		t.Fatalf("got %d hosts, want 1", len(hosts))
	}
	if got := hosts[0]["failedLogins"]; got != count {
		t.Fatalf("hosts[0].failedLogins = %v, want %d", got, count)
	}
	if got := hosts[0]["failedLoginsWindow"]; got != failedLoginsWindow {
		t.Fatalf("hosts[0].failedLoginsWindow = %v, want %q", got, failedLoginsWindow)
	}

	metrics, _ := telemetry["metrics"].(map[string]any)
	if got := metrics["failedLogins"]; got != count {
		t.Fatalf("metrics.failedLogins = %v, want %d", got, count)
	}
	if got := metrics["failedLoginsWindow"]; got != failedLoginsWindow {
		t.Fatalf("metrics.failedLoginsWindow = %v, want %q", got, failedLoginsWindow)
	}
}

func TestTelemetryKeepsMissingFailedLoginsNull(t *testing.T) {
	telemetry := processOverviewTelemetry(OverviewResponse{
		System: SystemSnapshot{Hostname: "host1.example.com"},
	})

	hosts, _ := telemetry["hosts"].([]map[string]any)
	if len(hosts) != 1 {
		t.Fatalf("got %d hosts, want 1", len(hosts))
	}
	if got, ok := hosts[0]["failedLogins"]; !ok || got != nil {
		t.Fatalf("hosts[0].failedLogins = %v (present %v), want null", got, ok)
	}

	metrics, _ := telemetry["metrics"].(map[string]any)
	if got, ok := metrics["failedLogins"]; !ok || got != nil {
		t.Fatalf("metrics.failedLogins = %v (present %v), want null", got, ok)
	}
}
