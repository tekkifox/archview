package service

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
)

func writeFailedLoginUsersFixture(t *testing.T, hostRoot, content string) {
	t.Helper()

	dir := filepath.Join(hostRoot, "var", "lib")
	if err := os.MkdirAll(dir, 0o700); err != nil {
		t.Fatalf("create failed-login-users fixture dir: %v", err)
	}
	if err := os.WriteFile(filepath.Join(dir, "ssh-failed-users.json"), []byte(content), 0o600); err != nil {
		t.Fatalf("write failed-login-users fixture: %v", err)
	}
}

func TestReadFailedLoginUsersParsesFile(t *testing.T) {
	hostRoot := t.TempDir()
	writeFailedLoginUsersFixture(t, hostRoot, `{"windowMinutes":60,"total":42,"users":[{"user":"root","count":30},{"user":"admin","count":12}]}`)

	got := readFailedLoginUsers(hostRoot)
	want := []FailedLoginUser{{User: "root", Count: 30}, {User: "admin", Count: 12}}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("readFailedLoginUsers = %#v, want %#v", got, want)
	}
}

func TestReadFailedLoginUsersMissingFileIsEmpty(t *testing.T) {
	got := readFailedLoginUsers(t.TempDir())
	if got == nil {
		t.Fatal("readFailedLoginUsers = nil, want an empty slice")
	}
	if len(got) != 0 {
		t.Fatalf("readFailedLoginUsers = %#v, want an empty slice", got)
	}
}

func TestReadFailedLoginUsersUnavailableIsEmpty(t *testing.T) {
	hostRoot := t.TempDir()
	writeFailedLoginUsersFixture(t, hostRoot, "unavailable\n")

	got := readFailedLoginUsers(hostRoot)
	if got == nil || len(got) != 0 {
		t.Fatalf("readFailedLoginUsers = %#v, want an empty slice for unavailable", got)
	}
}

func TestReadFailedLoginUsersMalformedJSONIsEmpty(t *testing.T) {
	hostRoot := t.TempDir()
	writeFailedLoginUsersFixture(t, hostRoot, `{"users":[{"user":"root"`)

	got := readFailedLoginUsers(hostRoot)
	if got == nil || len(got) != 0 {
		t.Fatalf("readFailedLoginUsers = %#v, want an empty slice for malformed JSON", got)
	}
}

func TestReadFailedLoginUsersDropsNumericUser(t *testing.T) {
	hostRoot := t.TempDir()
	writeFailedLoginUsersFixture(t, hostRoot, `{"users":[{"user":123,"count":5},{"user":"admin","count":3}]}`)

	got := readFailedLoginUsers(hostRoot)
	want := []FailedLoginUser{{User: "admin", Count: 3}}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("readFailedLoginUsers = %#v, want %#v", got, want)
	}
}

func TestReadFailedLoginUsersDropsNegativeCount(t *testing.T) {
	hostRoot := t.TempDir()
	writeFailedLoginUsersFixture(t, hostRoot, `{"users":[{"user":"root","count":-1},{"user":"admin","count":3}]}`)

	got := readFailedLoginUsers(hostRoot)
	want := []FailedLoginUser{{User: "admin", Count: 3}}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("readFailedLoginUsers = %#v, want %#v", got, want)
	}
}

func TestReadFailedLoginUsersTruncatesToTwentyPreservingOrder(t *testing.T) {
	hostRoot := t.TempDir()

	var entries []string
	var want []FailedLoginUser
	for i := 0; i < maxFailedLoginUsers+5; i++ {
		user := fmt.Sprintf("user%02d", i)
		entries = append(entries, fmt.Sprintf(`{"user":%q,"count":%d}`, user, 100-i))
		if i < maxFailedLoginUsers {
			want = append(want, FailedLoginUser{User: user, Count: 100 - i})
		}
	}
	writeFailedLoginUsersFixture(t, hostRoot, `{"users":[`+strings.Join(entries, ",")+`]}`)

	got := readFailedLoginUsers(hostRoot)
	if len(got) != maxFailedLoginUsers {
		t.Fatalf("readFailedLoginUsers returned %d entries, want %d", len(got), maxFailedLoginUsers)
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("readFailedLoginUsers = %#v, want the first %d entries in order", got, maxFailedLoginUsers)
	}
}

func TestSystemEndpointReportsFailedLoginUsers(t *testing.T) {
	hostRoot := t.TempDir()
	writeFailedLoginUsersFixture(t, hostRoot, `{"windowMinutes":60,"total":42,"users":[{"user":"root","count":30},{"user":"admin","count":12}]}`)

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
		FailedLoginUsers []FailedLoginUser `json:"failedLoginUsers"`
	}
	if err := json.Unmarshal(recorder.Body.Bytes(), &payload); err != nil {
		t.Fatalf("decode system response: %v", err)
	}
	want := []FailedLoginUser{{User: "root", Count: 30}, {User: "admin", Count: 12}}
	if !reflect.DeepEqual(payload.FailedLoginUsers, want) {
		t.Fatalf("failedLoginUsers = %#v, want %#v (body %s)", payload.FailedLoginUsers, want, recorder.Body.String())
	}
}

func TestSystemEndpointKeepsFailedLoginUsersEmptyWhenMissing(t *testing.T) {
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
	raw, ok := fields["failedLoginUsers"]
	if !ok {
		t.Fatalf("system response is missing failedLoginUsers: %s", recorder.Body.String())
	}
	if string(raw) != "[]" {
		t.Fatalf("failedLoginUsers = %s, want [] when the file is missing", raw)
	}
}

func TestTelemetryIncludesFailedLoginUsers(t *testing.T) {
	users := []FailedLoginUser{{User: "root", Count: 30}, {User: "admin", Count: 12}}
	telemetry := processOverviewTelemetry(OverviewResponse{
		System: SystemSnapshot{
			Hostname:           "host1.example.com",
			FailedLoginsWindow: failedLoginsWindow,
			FailedLoginUsers:   users,
		},
	})

	hosts, _ := telemetry["hosts"].([]map[string]any)
	if len(hosts) != 1 {
		t.Fatalf("got %d hosts, want 1", len(hosts))
	}
	if got := hosts[0]["failedLoginUsers"]; !reflect.DeepEqual(got, users) {
		t.Fatalf("hosts[0].failedLoginUsers = %#v, want %#v", got, users)
	}

	metrics, _ := telemetry["metrics"].(map[string]any)
	if got := metrics["failedLoginUsers"]; !reflect.DeepEqual(got, users) {
		t.Fatalf("metrics.failedLoginUsers = %#v, want %#v", got, users)
	}
}

func TestTelemetryKeepsMissingFailedLoginUsersEmpty(t *testing.T) {
	telemetry := processOverviewTelemetry(OverviewResponse{
		System: SystemSnapshot{Hostname: "host1.example.com"},
	})

	hosts, _ := telemetry["hosts"].([]map[string]any)
	if len(hosts) != 1 {
		t.Fatalf("got %d hosts, want 1", len(hosts))
	}
	want := []FailedLoginUser{}
	if got, ok := hosts[0]["failedLoginUsers"]; !ok || !reflect.DeepEqual(got, want) {
		t.Fatalf("hosts[0].failedLoginUsers = %#v (present %v), want %#v", got, ok, want)
	}

	metrics, _ := telemetry["metrics"].(map[string]any)
	if got, ok := metrics["failedLoginUsers"]; !ok || !reflect.DeepEqual(got, want) {
		t.Fatalf("metrics.failedLoginUsers = %#v (present %v), want %#v", got, ok, want)
	}
}
