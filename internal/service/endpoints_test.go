package service

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestRequestBaseURL(t *testing.T) {
	tests := []struct {
		name    string
		trust   bool
		scheme  string
		host    string
		headers map[string]string
		want    string
	}{
		{
			name:   "plain http",
			scheme: "http",
			host:   "archview.test",
			want:   "http://archview.test",
		},
		{
			name:   "plain https",
			scheme: "https",
			host:   "archview.test",
			want:   "https://archview.test",
		},
		{
			name:   "forwarded headers ignored when untrusted",
			scheme: "http",
			host:   "archview.test",
			headers: map[string]string{
				"X-Forwarded-Proto": "https",
				"X-Forwarded-Host":  "public.example",
			},
			want: "http://archview.test",
		},
		{
			name:   "forwarded headers trusted",
			trust:  true,
			scheme: "http",
			host:   "archview.test",
			headers: map[string]string{
				"X-Forwarded-Proto": "https",
				"X-Forwarded-Host":  "public.example",
			},
			want: "https://public.example",
		},
		{
			name:   "trusted forwarded headers keep ports",
			trust:  true,
			scheme: "http",
			host:   "archview.test",
			headers: map[string]string{
				"X-Forwarded-Proto": "https",
				"X-Forwarded-Host":  "public.example:8443",
			},
			want: "https://public.example:8443",
		},
		{
			name:   "tls wins without forwarded proto",
			trust:  true,
			scheme: "https",
			host:   "archview.test",
			want:   "https://archview.test",
		},
		{
			name:   "trusted forwarded proto overrides tls",
			trust:  true,
			scheme: "https",
			host:   "archview.test",
			headers: map[string]string{
				"X-Forwarded-Proto": "http",
			},
			want: "http://archview.test",
		},
		{
			name:   "forwarded host with scheme is rejected",
			trust:  true,
			scheme: "http",
			host:   "archview.test",
			headers: map[string]string{
				"X-Forwarded-Host": "https://evil.example",
			},
			want: "http://archview.test",
		},
		{
			name:   "forwarded host with path is rejected",
			trust:  true,
			scheme: "http",
			host:   "archview.test",
			headers: map[string]string{
				"X-Forwarded-Host": "evil.example/steal",
			},
			want: "http://archview.test",
		},
		{
			name:   "forwarded proto other than http or https is ignored",
			trust:  true,
			scheme: "http",
			host:   "archview.test",
			headers: map[string]string{
				"X-Forwarded-Proto": "javascript",
			},
			want: "http://archview.test",
		},
		{
			name:   "ipv6 host",
			scheme: "https",
			host:   "[::1]:8443",
			want:   "https://[::1]:8443",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			server := &Server{cfg: Config{Auth: AuthConfig{TrustProxyHeaders: tt.trust}}}
			request := httptest.NewRequest(http.MethodGet, tt.scheme+"://"+tt.host+"/api/overview", nil)
			for name, value := range tt.headers {
				request.Header.Set(name, value)
			}

			if got := server.requestBaseURL(request); got != tt.want {
				t.Fatalf("requestBaseURL() = %q, want %q", got, tt.want)
			}
		})
	}
}

func TestEndpointLinks(t *testing.T) {
	server := &Server{}
	request := httptest.NewRequest(http.MethodGet, "https://archview.example/api/architecture?project=demo", nil)

	links := server.endpointLinks(request)
	want := map[string]string{
		"overview":     "https://archview.example/api/overview",
		"architecture": "https://archview.example/api/architecture?project=<name>",
		"docker":       "https://archview.example/api/docker",
		"system":       "https://archview.example/api/system",
		"healthz":      "https://archview.example/healthz",
		"readyz":       "https://archview.example/readyz",
		"docs":         "https://archview.example/docs",
	}
	if len(links) != len(want) {
		t.Fatalf("got %d endpoint links, want %d: %+v", len(links), len(want), links)
	}
	for _, link := range links {
		expected, ok := want[link.Name]
		if !ok {
			t.Fatalf("unexpected endpoint link %q", link.Name)
		}
		if link.URL != expected {
			t.Fatalf("endpoint %q URL = %q, want %q", link.Name, link.URL, expected)
		}
	}
}

func TestOverviewResponsesIncludeEndpoints(t *testing.T) {
	docker := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		switch {
		case strings.HasSuffix(r.URL.Path, "/info"):
			_, _ = w.Write([]byte(`{"ServerVersion":"test"}`))
		case strings.HasSuffix(r.URL.Path, "/containers/json"):
			_, _ = w.Write([]byte(`[]`))
		case strings.HasSuffix(r.URL.Path, "/images/json"):
			_, _ = w.Write([]byte(`[]`))
		default:
			http.NotFound(w, r)
		}
	}))
	t.Cleanup(docker.Close)

	server, err := NewServer(Config{
		DockerHost: docker.URL,
		Auth:       AuthConfig{Mode: authModeNone},
	})
	if err != nil {
		t.Fatalf("NewServer: %v", err)
	}
	handler := server.Routes()

	tests := []struct {
		name    string
		target  string
		fullFor string
	}{
		{name: "overview", target: "/api/overview"},
		{name: "architecture project", target: "/api/architecture?project=demo"},
		{name: "architecture full docker project", target: "/api/architecture?project=demo", fullFor: "demo"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Setenv("FULL_DOCKER_PROJECTS", tt.fullFor)

			request := httptest.NewRequest(http.MethodGet, "https://archview.example"+tt.target, nil)
			recorder := httptest.NewRecorder()
			handler.ServeHTTP(recorder, request)

			if recorder.Code != http.StatusOK {
				t.Fatalf("status = %d, want 200 (body %s)", recorder.Code, recorder.Body.String())
			}

			var response OverviewResponse
			if err := json.Unmarshal(recorder.Body.Bytes(), &response); err != nil {
				t.Fatalf("decode response: %v", err)
			}
			if len(response.Endpoints) == 0 {
				t.Fatalf("response has no endpoints: %s", recorder.Body.String())
			}

			found := false
			for _, link := range response.Endpoints {
				if link.Name == "architecture" {
					found = true
					if want := "https://archview.example/api/architecture?project=<name>"; link.URL != want {
						t.Fatalf("architecture URL = %q, want %q", link.URL, want)
					}
				}
			}
			if !found {
				t.Fatalf("architecture endpoint missing from %+v", response.Endpoints)
			}

			var block strings.Builder
			block.WriteString("\nendpoints\n")
			for _, link := range response.Endpoints {
				block.WriteString("  - " + link.Name + ": " + link.URL + "\n")
			}
			if !strings.HasSuffix(response.Diagram, block.String()) {
				t.Fatalf("diagram does not end with the endpoints block:\n%s", response.Diagram)
			}
			if !strings.Contains(response.Diagram, "host linux system") {
				t.Fatalf("diagram lost its topology text:\n%s", response.Diagram)
			}
		})
	}
}
