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

func writeSSHLoginsFixture(t *testing.T, hostRoot, file, content string) {
	t.Helper()

	dir := filepath.Join(hostRoot, "var", "lib")
	if err := os.MkdirAll(dir, 0o700); err != nil {
		t.Fatalf("create ssh-logins fixture dir: %v", err)
	}
	if err := os.WriteFile(filepath.Join(dir, file), []byte(content), 0o600); err != nil {
		t.Fatalf("write ssh-logins fixture: %v", err)
	}
}

func TestReadSSHLoginsParsesHourlyFile(t *testing.T) {
	hostRoot := t.TempDir()
	writeSSHLoginsFixture(t, hostRoot, sshLoginUsersFile, `{"windowMinutes":60,"total":12,"users":[{"user":"root","count":9},{"user":"ross","count":3}]}`)

	got := readSSHLogins(hostRoot)
	if got.Total == nil || *got.Total != 12 {
		t.Fatalf("sshLogins total = %v, want 12", got.Total)
	}
	want := []SSHLoginUser{{User: "root", Count: 9}, {User: "ross", Count: 3}}
	if !reflect.DeepEqual(got.Users, want) {
		t.Fatalf("sshLoginUsers = %#v, want %#v", got.Users, want)
	}
	if got.Since != nil {
		t.Fatalf("hourly since = %q, want nil", *got.Since)
	}
}

func TestReadSSHLoginsTodayParsesDailyFile(t *testing.T) {
	hostRoot := t.TempDir()
	writeSSHLoginsFixture(t, hostRoot, sshLoginsTodayFile, `{"date":"2026-11-03","since":"2026-11-03T00:05:00Z","total":497,"users":[{"user":"root","count":288}]}`)

	got := readSSHLoginsToday(hostRoot)
	if got.Total == nil || *got.Total != 497 {
		t.Fatalf("sshLoginsToday total = %v, want 497", got.Total)
	}
	if got.Since == nil || *got.Since != "2026-11-03T00:05:00Z" {
		t.Fatalf("sshLoginsTodaySince = %v, want the file's verbatim timestamp", got.Since)
	}
	want := []SSHLoginUser{{User: "root", Count: 288}}
	if !reflect.DeepEqual(got.Users, want) {
		t.Fatalf("sshLoginUsersToday = %#v, want %#v", got.Users, want)
	}
}

func TestReadSSHLoginsMissingFileIsNull(t *testing.T) {
	got := readSSHLogins(t.TempDir())
	if got.Total != nil {
		t.Fatalf("sshLogins total = %d, want nil for a missing file", *got.Total)
	}
	if got.Users == nil || len(got.Users) != 0 {
		t.Fatalf("sshLoginUsers = %#v, want an empty non-nil slice", got.Users)
	}
}

func TestReadSSHLoginsEmptyRootIsNull(t *testing.T) {
	got := readSSHLogins("")
	if got.Total != nil {
		t.Fatalf("sshLogins total = %d, want nil when HOST_ROOT is empty", *got.Total)
	}
	if len(got.Users) != 0 {
		t.Fatalf("sshLoginUsers = %#v, want an empty slice", got.Users)
	}
}

func TestReadSSHLoginsUnavailableIsNull(t *testing.T) {
	hostRoot := t.TempDir()
	writeSSHLoginsFixture(t, hostRoot, sshLoginUsersFile, "unavailable\n")

	got := readSSHLogins(hostRoot)
	if got.Total != nil {
		t.Fatalf("sshLogins total = %d, want nil for unavailable", *got.Total)
	}
	if got.Users == nil || len(got.Users) != 0 {
		t.Fatalf("sshLoginUsers = %#v, want an empty non-nil slice", got.Users)
	}
}

func TestReadSSHLoginsMalformedJSONIsNull(t *testing.T) {
	hostRoot := t.TempDir()
	writeSSHLoginsFixture(t, hostRoot, sshLoginUsersFile, `{"total":12,"users":[{"user":"root"`)

	got := readSSHLogins(hostRoot)
	if got.Total != nil {
		t.Fatalf("sshLogins total = %d, want nil for malformed JSON", *got.Total)
	}
	if got.Users == nil || len(got.Users) != 0 {
		t.Fatalf("sshLoginUsers = %#v, want an empty non-nil slice", got.Users)
	}
}

func TestReadSSHLoginsTotalAsStringIsNull(t *testing.T) {
	hostRoot := t.TempDir()
	writeSSHLoginsFixture(t, hostRoot, sshLoginUsersFile, `{"total":"12","users":[{"user":"root","count":9}]}`)

	got := readSSHLogins(hostRoot)
	if got.Total != nil {
		t.Fatalf("sshLogins total = %d, want nil when total is a string", *got.Total)
	}
	want := []SSHLoginUser{{User: "root", Count: 9}}
	if !reflect.DeepEqual(got.Users, want) {
		t.Fatalf("sshLoginUsers = %#v, want %#v", got.Users, want)
	}
}

func TestReadSSHLoginUsersDropsNumericUser(t *testing.T) {
	hostRoot := t.TempDir()
	writeSSHLoginsFixture(t, hostRoot, sshLoginUsersFile, `{"total":8,"users":[{"user":123,"count":5},{"user":"admin","count":3}]}`)

	got := readSSHLogins(hostRoot)
	want := []SSHLoginUser{{User: "admin", Count: 3}}
	if !reflect.DeepEqual(got.Users, want) {
		t.Fatalf("sshLoginUsers = %#v, want %#v", got.Users, want)
	}
}

func TestReadSSHLoginUsersDropsNegativeCount(t *testing.T) {
	hostRoot := t.TempDir()
	writeSSHLoginsFixture(t, hostRoot, sshLoginUsersFile, `{"total":3,"users":[{"user":"root","count":-1},{"user":"admin","count":3}]}`)

	got := readSSHLogins(hostRoot)
	want := []SSHLoginUser{{User: "admin", Count: 3}}
	if !reflect.DeepEqual(got.Users, want) {
		t.Fatalf("sshLoginUsers = %#v, want %#v", got.Users, want)
	}
}

func TestReadSSHLoginUsersTruncatesToTwentyPreservingOrder(t *testing.T) {
	hostRoot := t.TempDir()

	var entries []string
	var want []SSHLoginUser
	for i := 0; i < maxSSHLoginUsers+5; i++ {
		user := fmt.Sprintf("user%02d", i)
		entries = append(entries, fmt.Sprintf(`{"user":%q,"count":%d}`, user, 100-i))
		if i < maxSSHLoginUsers {
			want = append(want, SSHLoginUser{User: user, Count: 100 - i})
		}
	}
	writeSSHLoginsFixture(t, hostRoot, sshLoginUsersFile, `{"total":500,"users":[`+strings.Join(entries, ",")+`]}`)

	got := readSSHLogins(hostRoot)
	if len(got.Users) != maxSSHLoginUsers {
		t.Fatalf("sshLoginUsers returned %d entries, want %d", len(got.Users), maxSSHLoginUsers)
	}
	if !reflect.DeepEqual(got.Users, want) {
		t.Fatalf("sshLoginUsers = %#v, want the first %d entries in order", got.Users, maxSSHLoginUsers)
	}
}

func TestReadSSHLoginsTodaySinceUnparseableIsNull(t *testing.T) {
	hostRoot := t.TempDir()
	writeSSHLoginsFixture(t, hostRoot, sshLoginsTodayFile, `{"date":"2026-11-03","since":"yesterday","total":4,"users":[]}`)

	got := readSSHLoginsToday(hostRoot)
	if got.Since != nil {
		t.Fatalf("sshLoginsTodaySince = %q, want nil for an unparseable timestamp", *got.Since)
	}
	if got.Total == nil || *got.Total != 4 {
		t.Fatalf("sshLoginsToday total = %v, want 4", got.Total)
	}
}

func TestSystemEndpointReportsSSHLogins(t *testing.T) {
	hostRoot := t.TempDir()
	writeSSHLoginsFixture(t, hostRoot, sshLoginUsersFile, `{"windowMinutes":60,"total":12,"users":[{"user":"root","count":9}]}`)
	writeSSHLoginsFixture(t, hostRoot, sshLoginsTodayFile, `{"date":"2026-11-03","since":"2026-11-03T00:05:00Z","total":497,"users":[{"user":"root","count":288}]}`)

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
		SSHLogins           *int           `json:"sshLogins"`
		SSHLoginUsers       []SSHLoginUser `json:"sshLoginUsers"`
		SSHLoginsToday      *int           `json:"sshLoginsToday"`
		SSHLoginUsersToday  []SSHLoginUser `json:"sshLoginUsersToday"`
		SSHLoginsTodaySince *string        `json:"sshLoginsTodaySince"`
	}
	if err := json.Unmarshal(recorder.Body.Bytes(), &payload); err != nil {
		t.Fatalf("decode system response: %v", err)
	}
	if payload.SSHLogins == nil || *payload.SSHLogins != 12 {
		t.Fatalf("sshLogins = %v, want 12 (body %s)", payload.SSHLogins, recorder.Body.String())
	}
	if want := []SSHLoginUser{{User: "root", Count: 9}}; !reflect.DeepEqual(payload.SSHLoginUsers, want) {
		t.Fatalf("sshLoginUsers = %#v, want %#v", payload.SSHLoginUsers, want)
	}
	if payload.SSHLoginsToday == nil || *payload.SSHLoginsToday != 497 {
		t.Fatalf("sshLoginsToday = %v, want 497 (body %s)", payload.SSHLoginsToday, recorder.Body.String())
	}
	if want := []SSHLoginUser{{User: "root", Count: 288}}; !reflect.DeepEqual(payload.SSHLoginUsersToday, want) {
		t.Fatalf("sshLoginUsersToday = %#v, want %#v", payload.SSHLoginUsersToday, want)
	}
	if payload.SSHLoginsTodaySince == nil || *payload.SSHLoginsTodaySince != "2026-11-03T00:05:00Z" {
		t.Fatalf("sshLoginsTodaySince = %v, want the file's verbatim timestamp", payload.SSHLoginsTodaySince)
	}
}

func TestSystemEndpointKeepsSSHLoginsNullWhenMissing(t *testing.T) {
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
	for _, field := range []string{"sshLogins", "sshLoginsToday", "sshLoginsTodaySince"} {
		raw, ok := fields[field]
		if !ok {
			t.Fatalf("system response is missing %s: %s", field, recorder.Body.String())
		}
		if string(raw) != "null" {
			t.Fatalf("%s = %s, want null when the file is missing", field, raw)
		}
	}
	for _, field := range []string{"sshLoginUsers", "sshLoginUsersToday"} {
		raw, ok := fields[field]
		if !ok {
			t.Fatalf("system response is missing %s: %s", field, recorder.Body.String())
		}
		if string(raw) != "[]" {
			t.Fatalf("%s = %s, want [] when the file is missing", field, raw)
		}
	}
}

func TestTelemetryIncludesSSHLogins(t *testing.T) {
	hourly := 12
	daily := 497
	since := "2026-11-03T00:05:00Z"
	hourlyUsers := []SSHLoginUser{{User: "root", Count: 9}}
	dailyUsers := []SSHLoginUser{{User: "root", Count: 288}}
	telemetry := processOverviewTelemetry(OverviewResponse{
		System: SystemSnapshot{
			Hostname:            "host1.example.com",
			SSHLogins:           &hourly,
			SSHLoginUsers:       hourlyUsers,
			SSHLoginsToday:      &daily,
			SSHLoginUsersToday:  dailyUsers,
			SSHLoginsTodaySince: &since,
		},
	})

	hosts, _ := telemetry["hosts"].([]map[string]any)
	if len(hosts) != 1 {
		t.Fatalf("got %d hosts, want 1", len(hosts))
	}
	if got := hosts[0]["sshLogins"]; got != hourly {
		t.Fatalf("hosts[0].sshLogins = %v, want %d", got, hourly)
	}
	if got := hosts[0]["sshLoginUsers"]; !reflect.DeepEqual(got, hourlyUsers) {
		t.Fatalf("hosts[0].sshLoginUsers = %#v, want %#v", got, hourlyUsers)
	}
	if got := hosts[0]["sshLoginsToday"]; got != daily {
		t.Fatalf("hosts[0].sshLoginsToday = %v, want %d", got, daily)
	}
	if got := hosts[0]["sshLoginUsersToday"]; !reflect.DeepEqual(got, dailyUsers) {
		t.Fatalf("hosts[0].sshLoginUsersToday = %#v, want %#v", got, dailyUsers)
	}
	if got := hosts[0]["sshLoginsTodaySince"]; got != since {
		t.Fatalf("hosts[0].sshLoginsTodaySince = %v, want %q", got, since)
	}

	metrics, _ := telemetry["metrics"].(map[string]any)
	for field, want := range map[string]any{
		"sshLogins":           hourly,
		"sshLoginUsers":       hourlyUsers,
		"sshLoginsToday":      daily,
		"sshLoginUsersToday":  dailyUsers,
		"sshLoginsTodaySince": since,
	} {
		if got := metrics[field]; !reflect.DeepEqual(got, want) {
			t.Fatalf("metrics.%s = %#v, want %#v", field, got, want)
		}
	}
}

func TestTelemetryKeepsMissingSSHLoginsNull(t *testing.T) {
	telemetry := processOverviewTelemetry(OverviewResponse{
		System: SystemSnapshot{Hostname: "host1.example.com"},
	})

	hosts, _ := telemetry["hosts"].([]map[string]any)
	if len(hosts) != 1 {
		t.Fatalf("got %d hosts, want 1", len(hosts))
	}
	for _, field := range []string{"sshLogins", "sshLoginsToday", "sshLoginsTodaySince"} {
		if got, ok := hosts[0][field]; !ok || got != nil {
			t.Fatalf("hosts[0].%s = %v (present %v), want null", field, got, ok)
		}
	}
	empty := []SSHLoginUser{}
	for _, field := range []string{"sshLoginUsers", "sshLoginUsersToday"} {
		if got, ok := hosts[0][field]; !ok || !reflect.DeepEqual(got, empty) {
			t.Fatalf("hosts[0].%s = %#v (present %v), want %#v", field, got, ok, empty)
		}
	}

	metrics, _ := telemetry["metrics"].(map[string]any)
	for _, field := range []string{"sshLogins", "sshLoginsToday", "sshLoginsTodaySince"} {
		if got, ok := metrics[field]; !ok || got != nil {
			t.Fatalf("metrics.%s = %v (present %v), want null", field, got, ok)
		}
	}
	for _, field := range []string{"sshLoginUsers", "sshLoginUsersToday"} {
		if got, ok := metrics[field]; !ok || !reflect.DeepEqual(got, empty) {
			t.Fatalf("metrics.%s = %#v (present %v), want %#v", field, got, ok, empty)
		}
	}
}
