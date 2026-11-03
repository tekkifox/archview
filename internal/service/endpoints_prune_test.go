package service

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"reflect"
	"strings"
	"sync/atomic"
	"testing"
)

func TestParseEndpoints(t *testing.T) {
	tests := []struct {
		name string
		raw  string
		want []ManagedEndpoint
	}{
		{name: "empty", raw: ""},
		{name: "whitespace", raw: "  \n "},
		{
			name: "comma separated",
			raw:  "rossmoney=1, host2 = 2",
			want: []ManagedEndpoint{
				{Key: "host2", PortainerEndpointID: 2},
				{Key: "rossmoney", PortainerEndpointID: 1},
			},
		},
		{
			name: "json array",
			raw:  `[{"key":"rossmoney","portainerEndpointId":1},{"key":"host2","portainerEndpointId":2}]`,
			want: []ManagedEndpoint{
				{Key: "host2", PortainerEndpointID: 2},
				{Key: "rossmoney", PortainerEndpointID: 1},
			},
		},
		{
			name: "json object",
			raw:  `{"rossmoney":1,"host2":2}`,
			want: []ManagedEndpoint{
				{Key: "host2", PortainerEndpointID: 2},
				{Key: "rossmoney", PortainerEndpointID: 1},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := ParseEndpoints(tt.raw)
			if err != nil {
				t.Fatalf("ParseEndpoints(%q): %v", tt.raw, err)
			}
			if !reflect.DeepEqual(got, tt.want) {
				t.Fatalf("ParseEndpoints(%q) = %+v, want %+v", tt.raw, got, tt.want)
			}
		})
	}
}

func TestParseEndpointsRejectsInvalidConfiguration(t *testing.T) {
	tests := []string{
		"rossmoney",
		"rossmoney=abc",
		"rossmoney=0",
		"../rossmoney=1",
		"rossmoney=1,rossmoney=2",
		`[{"key":"rossmoney"}]`,
		`[{"key":"rossmoney","portainerEndpointId":1},{"key":"rossmoney","portainerEndpointId":2}]`,
		`{"rossmoney":"one"}`,
		`not json`,
	}

	for _, raw := range tests {
		if _, err := ParseEndpoints(raw); err == nil {
			t.Errorf("ParseEndpoints(%q) succeeded, want an error", raw)
		}
	}
}

func TestNewServerRequiresPortainerConfiguration(t *testing.T) {
	base := Config{
		Endpoints: []ManagedEndpoint{{Key: "rossmoney", PortainerEndpointID: 1}},
		Auth:      AuthConfig{Mode: authModeNone},
	}
	if _, err := NewServer(base); err == nil || !strings.Contains(err.Error(), "PORTAINER_URL") {
		t.Fatalf("NewServer without PORTAINER_URL error = %v, want PORTAINER_URL", err)
	}
	base.PortainerURL = "https://portainer.example"
	if _, err := NewServer(base); err == nil || !strings.Contains(err.Error(), "PORTAINER_API_KEY") {
		t.Fatalf("NewServer without PORTAINER_API_KEY error = %v, want PORTAINER_API_KEY", err)
	}
	base.PortainerAPIKey = "key"
	if _, err := NewServer(base); err != nil {
		t.Fatalf("NewServer with complete Portainer configuration: %v", err)
	}
}

func newEndpointTestHandler(t *testing.T, portainerURL string, auth AuthConfig) http.Handler {
	t.Helper()
	server, err := NewServer(Config{
		Endpoints:       []ManagedEndpoint{{Key: "rossmoney", PortainerEndpointID: 7}},
		PortainerURL:    portainerURL,
		PortainerAPIKey: "test-portainer-key",
		Auth:            auth,
	})
	if err != nil {
		t.Fatalf("NewServer: %v", err)
	}
	return server.Routes()
}

func TestPruneImagesDanglingByDefault(t *testing.T) {
	var calls atomic.Int32
	portainer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		if r.Method != http.MethodPost {
			t.Errorf("method = %s, want POST", r.Method)
		}
		if r.URL.Path != "/api/endpoints/7/docker/images/prune" {
			t.Errorf("path = %q, want /api/endpoints/7/docker/images/prune", r.URL.Path)
		}
		if got := r.Header.Get("X-API-Key"); got != "test-portainer-key" {
			t.Errorf("X-API-Key = %q", got)
		}
		var filters map[string][]string
		if err := json.Unmarshal([]byte(r.URL.Query().Get("filters")), &filters); err != nil {
			t.Errorf("filters are not JSON: %v", err)
		}
		if !reflect.DeepEqual(filters["dangling"], []string{"true"}) {
			t.Errorf("filters dangling = %v, want [true]", filters["dangling"])
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"ImagesDeleted":[{"Deleted":"sha256:abc"},{"Untagged":"app:old"}],"SpaceReclaimed":123456}`))
	}))
	t.Cleanup(portainer.Close)

	handler := newEndpointTestHandler(t, portainer.URL, AuthConfig{Mode: authModeNone})
	request := httptest.NewRequest(http.MethodPost, "https://archview.example/api/endpoints/rossmoney/prune-images", nil)
	recorder := httptest.NewRecorder()
	handler.ServeHTTP(recorder, request)

	if recorder.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200 (body %s)", recorder.Code, recorder.Body.String())
	}
	if calls.Load() != 1 {
		t.Fatalf("Portainer calls = %d, want 1", calls.Load())
	}

	var response PruneImagesResponse
	if err := json.Unmarshal(recorder.Body.Bytes(), &response); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	if response.Endpoint != "rossmoney" || response.PortainerEndpointID != 7 {
		t.Fatalf("unexpected endpoint in response: %+v", response)
	}
	if response.Mode != "dangling" {
		t.Fatalf("mode = %q, want dangling", response.Mode)
	}
	if response.DeletedCount != 2 || response.SpaceReclaimedBytes != 123456 {
		t.Fatalf("unexpected prune result: %+v", response)
	}
	if len(response.ImagesDeleted) != 2 || response.ImagesDeleted[0].Deleted != "sha256:abc" || response.ImagesDeleted[1].Untagged != "app:old" {
		t.Fatalf("unexpected images: %+v", response.ImagesDeleted)
	}
}

func TestPruneImagesAllUnusedImagesOptIn(t *testing.T) {
	portainer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var filters map[string][]string
		if err := json.Unmarshal([]byte(r.URL.Query().Get("filters")), &filters); err != nil {
			t.Errorf("filters are not JSON: %v", err)
		}
		if !reflect.DeepEqual(filters["dangling"], []string{"false"}) {
			t.Errorf("filters dangling = %v, want [false]", filters["dangling"])
		}
		_, _ = w.Write([]byte(`{"ImagesDeleted":[],"SpaceReclaimed":0}`))
	}))
	t.Cleanup(portainer.Close)

	handler := newEndpointTestHandler(t, portainer.URL, AuthConfig{Mode: authModeNone})
	request := httptest.NewRequest(http.MethodPost, "https://archview.example/api/endpoints/rossmoney/prune-images?all=true", nil)
	recorder := httptest.NewRecorder()
	handler.ServeHTTP(recorder, request)

	if recorder.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200 (body %s)", recorder.Code, recorder.Body.String())
	}
	var response PruneImagesResponse
	if err := json.Unmarshal(recorder.Body.Bytes(), &response); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	if response.Mode != "all" {
		t.Fatalf("mode = %q, want all", response.Mode)
	}
}

func TestPruneImagesUnknownEndpoint(t *testing.T) {
	var calls atomic.Int32
	portainer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
	}))
	t.Cleanup(portainer.Close)

	handler := newEndpointTestHandler(t, portainer.URL, AuthConfig{Mode: authModeNone})
	request := httptest.NewRequest(http.MethodPost, "https://archview.example/api/endpoints/unknown/prune-images", nil)
	recorder := httptest.NewRecorder()
	handler.ServeHTTP(recorder, request)

	if recorder.Code != http.StatusNotFound {
		t.Fatalf("status = %d, want 404 (body %s)", recorder.Code, recorder.Body.String())
	}
	if calls.Load() != 0 {
		t.Fatalf("Portainer was called %d times for an unknown endpoint", calls.Load())
	}
}

func TestPruneImagesSurfacesPortainerFailure(t *testing.T) {
	portainer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "portainer exploded", http.StatusInternalServerError)
	}))
	t.Cleanup(portainer.Close)

	handler := newEndpointTestHandler(t, portainer.URL, AuthConfig{Mode: authModeNone})
	request := httptest.NewRequest(http.MethodPost, "https://archview.example/api/endpoints/rossmoney/prune-images", nil)
	recorder := httptest.NewRecorder()
	handler.ServeHTTP(recorder, request)

	if recorder.Code == http.StatusOK {
		t.Fatalf("Portainer failure must not be reported as success: %s", recorder.Body.String())
	}
	if recorder.Code != http.StatusBadGateway {
		t.Fatalf("status = %d, want 502 (body %s)", recorder.Code, recorder.Body.String())
	}
	body := recorder.Body.String()
	if !strings.Contains(body, "500") || !strings.Contains(body, "portainer exploded") {
		t.Fatalf("error does not describe the Portainer failure: %s", body)
	}
}

func TestPruneImagesRequiresAuthentication(t *testing.T) {
	handler := newEndpointTestHandler(t, "https://portainer.example", AuthConfig{
		Mode:          authModeOIDC,
		IssuerURL:     "http://127.0.0.1:1",
		ClientID:      "archview",
		SessionSecret: testSessionSecret,
	})
	request := httptest.NewRequest(http.MethodPost, "https://archview.example/api/endpoints/rossmoney/prune-images", nil)
	recorder := httptest.NewRecorder()
	handler.ServeHTTP(recorder, request)

	if recorder.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d, want 401 (body %s)", recorder.Code, recorder.Body.String())
	}
}

func TestPruneImagesRejectsNonAdminPrincipal(t *testing.T) {
	server, err := NewServer(Config{
		Auth: AuthConfig{
			Mode:          authModeOIDC,
			IssuerURL:     "http://127.0.0.1:1",
			ClientID:      "archview",
			SessionSecret: testSessionSecret,
		},
		EndpointAdminEmails: []string{"admin@example.com"},
	})
	if err != nil {
		t.Fatalf("NewServer: %v", err)
	}

	principal := Principal{Subject: "user-1", Email: "user@example.com", Method: "session"}
	request := httptest.NewRequest(http.MethodPost, "https://archview.example/api/endpoints/rossmoney/prune-images", nil)
	request = request.WithContext(context.WithValue(request.Context(), principalContextKey{}, principal))
	recorder := httptest.NewRecorder()

	if server.authorizeEndpointAdmin(recorder, request) {
		t.Fatal("non-admin principal was authorised")
	}
	if recorder.Code != http.StatusForbidden {
		t.Fatalf("status = %d, want 403 (body %s)", recorder.Code, recorder.Body.String())
	}
}

func TestEndpointAdminAuthorization(t *testing.T) {
	newServer := func(t *testing.T, emails, clients []string) *Server {
		t.Helper()
		server, err := NewServer(Config{
			Auth: AuthConfig{
				Mode:          authModeOIDC,
				IssuerURL:     "http://127.0.0.1:1",
				ClientID:      "archview",
				SessionSecret: testSessionSecret,
			},
			EndpointAdminEmails:  emails,
			EndpointAdminClients: clients,
		})
		if err != nil {
			t.Fatalf("NewServer: %v", err)
		}
		return server
	}

	tests := []struct {
		name      string
		emails    []string
		clients   []string
		principal Principal
		want      bool
	}{
		{
			name:      "human admin",
			emails:    []string{"Admin@Example.com"},
			principal: Principal{Email: "admin@example.com", Method: "session"},
			want:      true,
		},
		{
			name:      "human not admin",
			emails:    []string{"admin@example.com"},
			principal: Principal{Email: "user@example.com", Method: "session"},
		},
		{
			name:      "machine admin client",
			clients:   []string{"cron"},
			principal: Principal{Name: "cron", Method: "client_credentials"},
			want:      true,
		},
		{
			name:      "machine not admin",
			clients:   []string{"cron"},
			principal: Principal{Name: "cms", Method: "client_credentials"},
		},
		{
			name:      "no admin configuration fails closed",
			principal: Principal{Email: "admin@example.com", Method: "session"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			server := newServer(t, tt.emails, tt.clients)
			request := httptest.NewRequest(http.MethodPost, "https://archview.example/api/endpoints/rossmoney/prune-images", nil)
			request = request.WithContext(context.WithValue(request.Context(), principalContextKey{}, tt.principal))
			recorder := httptest.NewRecorder()

			if got := server.authorizeEndpointAdmin(recorder, request); got != tt.want {
				t.Fatalf("authorizeEndpointAdmin() = %v, want %v (body %s)", got, tt.want, recorder.Body.String())
			}
		})
	}
}
