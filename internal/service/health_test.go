package service

import (
	"encoding/json"
	"net"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func newHealthHandler(t *testing.T, cfg Config) http.Handler {
	t.Helper()
	cfg.Auth = AuthConfig{Mode: authModeNone}
	server, err := NewServer(cfg)
	if err != nil {
		t.Fatalf("NewServer: %v", err)
	}
	return server.Routes()
}

func getHealth(t *testing.T, handler http.Handler) (int, map[string]any) {
	t.Helper()
	recorder := httptest.NewRecorder()
	handler.ServeHTTP(recorder, httptest.NewRequest(http.MethodGet, "http://archview.test/healthz", nil))

	var body map[string]any
	if err := json.Unmarshal(recorder.Body.Bytes(), &body); err != nil {
		t.Fatalf("decode health response %q: %v", recorder.Body.String(), err)
	}
	return recorder.Code, body
}

func TestHealthSucceedsWhenDockerReachable(t *testing.T) {
	var paths []string
	docker := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		paths = append(paths, r.URL.Path)
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"Version":"27.0.0","ApiVersion":"1.46"}`))
	}))
	t.Cleanup(docker.Close)

	code, body := getHealth(t, newHealthHandler(t, Config{
		DockerHost: docker.URL,
		DockerAPI:  "v1.41",
	}))
	if code != http.StatusOK {
		t.Fatalf("status = %d, want 200 (body %v)", code, body)
	}
	if body["status"] != "ok" {
		t.Fatalf("status field = %v, want ok", body["status"])
	}
	if _, ok := body["time"]; !ok {
		t.Fatalf("successful response lost its time field: %v", body)
	}
	if _, ok := body["reason"]; ok {
		t.Fatalf("successful response should not carry a reason: %v", body)
	}
	if len(paths) != 1 || paths[0] != "/v1.41/version" {
		t.Fatalf("probe paths = %v, want exactly [/v1.41/version]", paths)
	}
}

func TestHealthFailsWhenDockerUnreachable(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("reserve port: %v", err)
	}
	addr := listener.Addr().String()
	if err := listener.Close(); err != nil {
		t.Fatalf("close reserved port: %v", err)
	}

	code, body := getHealth(t, newHealthHandler(t, Config{
		DockerHost: "http://" + addr,
		DockerAPI:  "v1.41",
	}))
	if code != http.StatusServiceUnavailable {
		t.Fatalf("status = %d, want 503 (body %v)", code, body)
	}
	if body["status"] != "unhealthy" {
		t.Fatalf("status field = %v, want unhealthy", body["status"])
	}
	if body["reason"] != healthReasonDockerUnreachable {
		t.Fatalf("reason = %v, want %q", body["reason"], healthReasonDockerUnreachable)
	}
}

func TestHealthSkipsProbeWhenDockerNotConfigured(t *testing.T) {
	// No DockerHost: the unix socket is never dialled, so an absent daemon
	// cannot fail the check.
	code, body := getHealth(t, newHealthHandler(t, Config{
		DockerSock: "/nonexistent/archview-test/docker.sock",
		DockerAPI:  "v1.41",
	}))
	if code != http.StatusOK {
		t.Fatalf("status = %d, want 200 (body %v)", code, body)
	}
	if body["status"] != "ok" {
		t.Fatalf("status field = %v, want ok", body["status"])
	}
	if _, ok := body["reason"]; ok {
		t.Fatalf("response should not carry a reason: %v", body)
	}
}

func TestHealthTimesOutWhenDockerHangs(t *testing.T) {
	docker := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		<-r.Context().Done()
	}))
	t.Cleanup(docker.Close)

	start := time.Now()
	code, body := getHealth(t, newHealthHandler(t, Config{
		DockerHost: docker.URL,
		DockerAPI:  "v1.41",
	}))
	elapsed := time.Since(start)

	if code != http.StatusServiceUnavailable {
		t.Fatalf("status = %d, want 503 (body %v)", code, body)
	}
	if body["reason"] != healthReasonDockerTimeout {
		t.Fatalf("reason = %v, want %q", body["reason"], healthReasonDockerTimeout)
	}
	if elapsed > dockerProbeTimeout+2*time.Second {
		t.Fatalf("probe took %s, want it bounded by %s", elapsed, dockerProbeTimeout)
	}
}
