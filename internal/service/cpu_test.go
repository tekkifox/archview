package service

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// procStatFixtures are a pair of aggregate cpu lines 400 jiffies apart, of
// which 200 were busy: 50.0%.
const (
	procStatFirst  = "cpu  100 0 50 850 0 0 0 0 0 0\n"
	procStatSecond = "cpu  300 0 50 1050 0 0 0 0 0 0\n"
)

func writeProcStat(t *testing.T, dir, content string) {
	t.Helper()
	if err := os.WriteFile(filepath.Join(dir, "stat"), []byte(content), 0o600); err != nil {
		t.Fatalf("write stat fixture: %v", err)
	}
}

func floatPtr(value float64) *float64 { return &value }

func TestCPUPercentBetween(t *testing.T) {
	tests := []struct {
		name    string
		prev    cpuSample
		next    cpuSample
		want    *float64
		wantNil bool
	}{
		{
			name: "known window",
			prev: cpuSample{busy: 150, total: 1000},
			next: cpuSample{busy: 350, total: 1400},
			want: floatPtr(50.0),
		},
		{
			name: "idle only",
			prev: cpuSample{busy: 0, total: 1000},
			next: cpuSample{busy: 0, total: 2000},
			want: floatPtr(0.0),
		},
		{
			name: "all busy",
			prev: cpuSample{busy: 1000, total: 1000},
			next: cpuSample{busy: 1500, total: 1500},
			want: floatPtr(100.0),
		},
		{
			name: "rounds to one decimal",
			prev: cpuSample{busy: 0, total: 1000},
			next: cpuSample{busy: 100, total: 1300},
			want: floatPtr(33.3),
		},
		{
			name: "clamps to 100",
			prev: cpuSample{busy: 0, total: 100},
			next: cpuSample{busy: 500, total: 200},
			want: floatPtr(100.0),
		},
		{
			name:    "zero delta",
			prev:    cpuSample{busy: 100, total: 1000},
			next:    cpuSample{busy: 100, total: 1000},
			wantNil: true,
		},
		{
			name:    "counters went backwards",
			prev:    cpuSample{busy: 500, total: 1000},
			next:    cpuSample{busy: 100, total: 500},
			wantNil: true,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			got := cpuPercentBetween(test.prev, test.next)
			if test.wantNil {
				if got != nil {
					t.Fatalf("cpuPercentBetween() = %v, want nil", *got)
				}
				return
			}
			if got == nil {
				t.Fatal("cpuPercentBetween() = nil, want a value")
			}
			if *got != *test.want {
				t.Fatalf("cpuPercentBetween() = %v, want %v", *got, *test.want)
			}
		})
	}
}

func TestReadCPUPercentUsesFixturePair(t *testing.T) {
	dir := t.TempDir()
	writeProcStat(t, dir, procStatFirst)

	got := measureCPUPercent(dir, 0, func(time.Duration) {
		writeProcStat(t, dir, procStatSecond)
	})
	if got == nil {
		t.Fatal("measureCPUPercent() = nil, want 50.0")
	}
	if *got != 50.0 {
		t.Fatalf("measureCPUPercent() = %v, want 50.0", *got)
	}
}

func TestReadCPUPercentIdleOnlyFixture(t *testing.T) {
	dir := t.TempDir()
	writeProcStat(t, dir, "cpu  0 0 0 1000 0 0 0 0 0 0\n")

	got := measureCPUPercent(dir, 0, func(time.Duration) {
		writeProcStat(t, dir, "cpu  0 0 0 2000 0 0 0 0 0 0\n")
	})
	if got == nil {
		t.Fatal("measureCPUPercent() = nil, want 0.0")
	}
	if *got != 0.0 {
		t.Fatalf("measureCPUPercent() = %v, want 0.0", *got)
	}
}

func TestReadCPUPercentAllBusyFixture(t *testing.T) {
	dir := t.TempDir()
	writeProcStat(t, dir, "cpu  500 0 500 0 0 0 0 0 0 0\n")

	got := measureCPUPercent(dir, 0, func(time.Duration) {
		writeProcStat(t, dir, "cpu  750 0 750 0 0 0 0 0 0 0\n")
	})
	if got == nil {
		t.Fatal("measureCPUPercent() = nil, want 100.0")
	}
	if *got != 100.0 {
		t.Fatalf("measureCPUPercent() = %v, want 100.0", *got)
	}
}

func TestReadCPUPercentMissingStat(t *testing.T) {
	if got := readCPUPercent(t.TempDir()); got != nil {
		t.Fatalf("readCPUPercent() = %v, want nil when stat is missing", *got)
	}
}

func TestReadCPUPercentMalformedLine(t *testing.T) {
	for name, content := range map[string]string{
		"non-numeric field": "cpu  1 2 not-a-number 4 5\n",
		"too few fields":    "cpu  1 2 3\n",
		"no cpu line":       "intr 0 1 2\nctxt 3 4\n",
		"all zero":          "cpu  0 0 0 0 0 0 0 0 0 0\n",
	} {
		t.Run(name, func(t *testing.T) {
			dir := t.TempDir()
			writeProcStat(t, dir, content)
			if got := readCPUPercent(dir); got != nil {
				t.Fatalf("readCPUPercent() = %v, want nil for malformed stat", *got)
			}
		})
	}
}

func TestReadCPUPercentSecondReadFails(t *testing.T) {
	dir := t.TempDir()
	writeProcStat(t, dir, procStatFirst)

	got := measureCPUPercent(dir, 0, func(time.Duration) {
		if err := os.Remove(filepath.Join(dir, "stat")); err != nil {
			t.Fatalf("remove stat fixture: %v", err)
		}
	})
	if got != nil {
		t.Fatalf("measureCPUPercent() = %v, want nil when the second read fails", *got)
	}
}

func TestReadCPUPercentZeroDelta(t *testing.T) {
	dir := t.TempDir()
	writeProcStat(t, dir, procStatFirst)

	if got := readCPUPercent(dir); got != nil {
		t.Fatalf("readCPUPercent() = %v, want nil when no CPU time elapsed", *got)
	}
}

func TestCollectSystemReportsCPUPercentAndKeepsLoadAverage(t *testing.T) {
	dir := t.TempDir()
	writeProcStat(t, dir, procStatFirst)
	if err := os.WriteFile(filepath.Join(dir, "loadavg"), []byte("8.50 4.00 2.00 1/100 12345\n"), 0o600); err != nil {
		t.Fatalf("write loadavg fixture: %v", err)
	}

	// The real helper sleeps cpuSampleInterval between readings; advance the
	// fixture from a goroutine while it waits.
	done := make(chan struct{})
	go func() {
		defer close(done)
		time.Sleep(20 * time.Millisecond)
		_ = os.WriteFile(filepath.Join(dir, "stat"), []byte(procStatSecond), 0o600)
	}()

	system, err := collectSystemForTest(t, Config{HostProc: dir, HostRoot: dir})
	<-done
	if err != nil {
		t.Fatalf("collectSystem: %v", err)
	}
	if system.CPUPercent == nil {
		t.Fatal("CPUPercent = nil, want 50.0")
	}
	if *system.CPUPercent != 50.0 {
		t.Fatalf("CPUPercent = %v, want 50.0", *system.CPUPercent)
	}
	wantLoad := []float64{8.5, 4, 2}
	if len(system.LoadAverage) != len(wantLoad) {
		t.Fatalf("LoadAverage = %v, want %v", system.LoadAverage, wantLoad)
	}
	for i := range wantLoad {
		if system.LoadAverage[i] != wantLoad[i] {
			t.Fatalf("LoadAverage = %v, want %v", system.LoadAverage, wantLoad)
		}
	}
}

func TestCollectSystemOmitsCPUPercentWhenStatMissing(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "loadavg"), []byte("8.50 4.00 2.00 1/100 12345\n"), 0o600); err != nil {
		t.Fatalf("write loadavg fixture: %v", err)
	}

	system, err := collectSystemForTest(t, Config{HostProc: dir, HostRoot: dir})
	if err != nil {
		t.Fatalf("collectSystem: %v", err)
	}
	if system.CPUPercent != nil {
		t.Fatalf("CPUPercent = %v, want nil", *system.CPUPercent)
	}
	if len(system.LoadAverage) != 3 || system.LoadAverage[0] != 8.5 {
		t.Fatalf("LoadAverage = %v, want [8.5 4 2]", system.LoadAverage)
	}
}

func TestSystemEndpointOmitsCPUPercentWhenUnmeasured(t *testing.T) {
	handler := newResponseShapeServer(t).Routes()
	body := string(getJSON(t, handler, "/api/system"))

	if strings.Contains(body, `"cpuPercent"`) {
		t.Fatalf("/api/system published a CPU figure it could not measure: %s", body)
	}
	if !strings.Contains(body, `"loadAverage"`) {
		t.Fatalf("/api/system dropped the load average: %s", body)
	}
}

func TestTelemetryUsesMeasuredCPUAndKeepsLoadAverage(t *testing.T) {
	resp := OverviewResponse{System: SystemSnapshot{
		Hostname:    "host1.example.com",
		CPUCount:    2,
		LoadAverage: []float64{8.5, 4, 2},
		CPUPercent:  floatPtr(12.5),
	}}

	telemetry := processOverviewTelemetry(resp)
	host := telemetry["hosts"].([]map[string]any)[0]
	if got := host["cpu"]; got != 12.5 {
		t.Fatalf("hosts[0].cpu = %v, want 12.5", got)
	}
	load, ok := host["loadAverage"].([]float64)
	if !ok || len(load) != 3 || load[0] != 8.5 {
		t.Fatalf("hosts[0].loadAverage = %v, want [8.5 4 2]", host["loadAverage"])
	}

	metrics := telemetry["metrics"].(map[string]any)
	if got := metrics["cpuAvg"]; got != 12.5 {
		t.Fatalf("metrics.cpuAvg = %v, want 12.5", got)
	}
	if got := metrics["loadAvg"]; got != 8.5 {
		t.Fatalf("metrics.loadAvg = %v, want 8.5", got)
	}
}

func TestTelemetryOmitsCPUWhenUnmeasured(t *testing.T) {
	resp := OverviewResponse{System: SystemSnapshot{
		Hostname:    "host1.example.com",
		CPUCount:    2,
		LoadAverage: []float64{8.5, 4, 2},
	}}

	telemetry := processOverviewTelemetry(resp)
	host := telemetry["hosts"].([]map[string]any)[0]
	if _, ok := host["cpu"]; ok {
		t.Fatalf("hosts[0] carries cpu = %v, want the field omitted", host["cpu"])
	}
	metrics := telemetry["metrics"].(map[string]any)
	if _, ok := metrics["cpuAvg"]; ok {
		t.Fatalf("metrics carries cpuAvg = %v, want the field omitted", metrics["cpuAvg"])
	}
	if got := metrics["loadAvg"]; got != 8.5 {
		t.Fatalf("metrics.loadAvg = %v, want 8.5", got)
	}
}

func collectSystemForTest(t *testing.T, cfg Config) (SystemSnapshot, error) {
	t.Helper()
	server, err := NewServer(cfg)
	if err != nil {
		t.Fatalf("NewServer: %v", err)
	}
	return server.collectSystem(context.Background())
}

func TestSystemEndpointPublishesMeasuredCPU(t *testing.T) {
	dir := t.TempDir()
	writeProcStat(t, dir, procStatFirst)

	server, err := NewServer(Config{HostProc: dir, HostRoot: dir, Auth: AuthConfig{Mode: authModeNone}})
	if err != nil {
		t.Fatalf("NewServer: %v", err)
	}
	done := make(chan struct{})
	go func() {
		defer close(done)
		time.Sleep(20 * time.Millisecond)
		_ = os.WriteFile(filepath.Join(dir, "stat"), []byte(procStatSecond), 0o600)
	}()

	request := httptest.NewRequest(http.MethodGet, "https://archview.example/api/system", nil)
	recorder := httptest.NewRecorder()
	server.Routes().ServeHTTP(recorder, request)
	<-done

	if recorder.Code != http.StatusOK {
		t.Fatalf("GET /api/system status = %d, want 200 (body %s)", recorder.Code, recorder.Body.String())
	}
	var payload map[string]any
	if err := json.Unmarshal(recorder.Body.Bytes(), &payload); err != nil {
		t.Fatalf("decode /api/system: %v", err)
	}
	got, ok := payload["cpuPercent"].(float64)
	if !ok {
		t.Fatalf("/api/system cpuPercent = %v, want 50.0 (body %s)", payload["cpuPercent"], recorder.Body.String())
	}
	if got != 50.0 {
		t.Fatalf("/api/system cpuPercent = %v, want 50.0", got)
	}
	if _, ok := payload["loadAverage"]; !ok {
		t.Fatalf("/api/system dropped loadAverage: %s", recorder.Body.String())
	}
}
