package service

import (
	"bytes"
	"context"
	"encoding/json"
	"log"
	"net/http"
	"net/http/httptest"
	"reflect"
	"strings"
	"sync/atomic"
	"testing"
	"time"
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
	newServer := func(t *testing.T, emails, clients []string, scope string) *Server {
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
			EndpointAdminScope:   scope,
		})
		if err != nil {
			t.Fatalf("NewServer: %v", err)
		}
		return server
	}

	tests := []struct {
		name       string
		emails     []string
		clients    []string
		adminScope string
		principal  Principal
		want       bool
		wantBody   string
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
			wantBody:  "this account is not allowed to manage endpoints",
		},
		{
			name:      "machine admin with allowlist and scope",
			clients:   []string{"cron"},
			principal: Principal{Name: "cron", Method: "client_credentials", Scopes: []string{"endpoints:admin"}},
			want:      true,
		},
		{
			name:      "machine allowlisted without the admin scope",
			clients:   []string{"cron"},
			principal: Principal{Name: "cron", Method: "client_credentials", Scopes: []string{"archview:read"}},
			wantBody:  "endpoints:admin",
		},
		{
			name:      "machine with the admin scope but not allowlisted",
			clients:   []string{"cron"},
			principal: Principal{Name: "cms", Method: "client_credentials", Scopes: []string{"endpoints:admin"}},
			wantBody:  "ENDPOINTS_ADMIN_CLIENTS",
		},
		{
			name:       "custom admin scope is honoured",
			clients:    []string{"cron"},
			adminScope: "ops:prune",
			principal:  Principal{Name: "cron", Method: "client_credentials", Scopes: []string{"ops:prune"}},
			want:       true,
		},
		{
			name:       "default scope is refused when overridden",
			clients:    []string{"cron"},
			adminScope: "ops:prune",
			principal:  Principal{Name: "cron", Method: "client_credentials", Scopes: []string{"endpoints:admin"}},
			wantBody:   "ops:prune",
		},
		{
			name:      "machine not admin",
			clients:   []string{"cron"},
			principal: Principal{Name: "cms", Method: "client_credentials", Scopes: []string{"endpoints:admin"}},
			wantBody:  "ENDPOINTS_ADMIN_CLIENTS",
		},
		{
			name:      "no admin configuration fails closed",
			principal: Principal{Email: "admin@example.com", Method: "session"},
			wantBody:  "endpoint administration is not configured",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			server := newServer(t, tt.emails, tt.clients, tt.adminScope)
			request := httptest.NewRequest(http.MethodPost, "https://archview.example/api/endpoints/rossmoney/prune-images", nil)
			request = request.WithContext(context.WithValue(request.Context(), principalContextKey{}, tt.principal))
			recorder := httptest.NewRecorder()

			if got := server.authorizeEndpointAdmin(recorder, request); got != tt.want {
				t.Fatalf("authorizeEndpointAdmin() = %v, want %v (body %s)", got, tt.want, recorder.Body.String())
			}
			if tt.wantBody != "" && !strings.Contains(recorder.Body.String(), tt.wantBody) {
				t.Fatalf("refusal body %s does not mention %q", recorder.Body.String(), tt.wantBody)
			}
		})
	}
}

func newEndpointTestServer(t *testing.T, portainerURL string, cfg Config) *Server {
	t.Helper()
	cfg.Endpoints = []ManagedEndpoint{{Key: "rossmoney", PortainerEndpointID: 7}}
	cfg.PortainerURL = portainerURL
	cfg.PortainerAPIKey = "test-portainer-key"
	server, err := NewServer(cfg)
	if err != nil {
		t.Fatalf("NewServer: %v", err)
	}
	return server
}

func endpointAdminTestAuth() AuthConfig {
	return AuthConfig{
		Mode:          authModeOIDC,
		IssuerURL:     "http://127.0.0.1:1",
		ClientID:      "archview",
		SessionSecret: testSessionSecret,
	}
}

func TestPruneImagesMachineCallerNeedsScopeAndAllowlist(t *testing.T) {
	tests := []struct {
		name        string
		emails      []string
		clients     []string
		adminScope  string
		principal   Principal
		wantStatus  int
		wantMessage string
	}{
		{
			name:        "read scope alone is refused even when allowlisted",
			clients:     []string{"cron"},
			principal:   Principal{Name: "cron", Method: "client_credentials", Scopes: []string{"archview:read"}},
			wantStatus:  http.StatusForbidden,
			wantMessage: "endpoints:admin",
		},
		{
			name:        "scope without allowlist entry is refused",
			clients:     []string{"cron"},
			principal:   Principal{Name: "cms", Method: "client_credentials", Scopes: []string{"endpoints:admin"}},
			wantStatus:  http.StatusForbidden,
			wantMessage: "ENDPOINTS_ADMIN_CLIENTS",
		},
		{
			name:       "scope and allowlist entry proceed",
			clients:    []string{"cron"},
			principal:  Principal{Name: "cron", Method: "client_credentials", Scopes: []string{"endpoints:admin"}},
			wantStatus: http.StatusOK,
		},
		{
			name:       "custom scope from ENDPOINTS_ADMIN_SCOPE is honoured",
			clients:    []string{"cron"},
			adminScope: "ops:prune",
			principal:  Principal{Name: "cron", Method: "client_credentials", Scopes: []string{"ops:prune"}},
			wantStatus: http.StatusOK,
		},
		{
			name:        "default scope is not accepted when ENDPOINTS_ADMIN_SCOPE overrides it",
			clients:     []string{"cron"},
			adminScope:  "ops:prune",
			principal:   Principal{Name: "cron", Method: "client_credentials", Scopes: []string{"endpoints:admin"}},
			wantStatus:  http.StatusForbidden,
			wantMessage: "ops:prune",
		},
		{
			name:       "oidc user on the email allowlist is unaffected by the scope rule",
			emails:     []string{"admin@example.com"},
			principal:  Principal{Email: "admin@example.com", Method: "session"},
			wantStatus: http.StatusOK,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var calls atomic.Int32
			portainer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				calls.Add(1)
				_, _ = w.Write([]byte(`{"ImagesDeleted":[],"SpaceReclaimed":0}`))
			}))
			t.Cleanup(portainer.Close)

			server := newEndpointTestServer(t, portainer.URL, Config{
				Auth:                 endpointAdminTestAuth(),
				EndpointAdminEmails:  tt.emails,
				EndpointAdminClients: tt.clients,
				EndpointAdminScope:   tt.adminScope,
			})
			request := httptest.NewRequest(http.MethodPost, "https://archview.example/api/endpoints/rossmoney/prune-images", nil)
			request = request.WithContext(context.WithValue(request.Context(), principalContextKey{}, tt.principal))
			recorder := httptest.NewRecorder()

			server.handleEndpointRoute(recorder, request)

			if recorder.Code != tt.wantStatus {
				t.Fatalf("status = %d, want %d (body %s)", recorder.Code, tt.wantStatus, recorder.Body.String())
			}
			if tt.wantMessage != "" && !strings.Contains(recorder.Body.String(), tt.wantMessage) {
				t.Fatalf("response %s does not mention %q", recorder.Body.String(), tt.wantMessage)
			}
			wantCalls := int32(0)
			if tt.wantStatus == http.StatusOK {
				wantCalls = 1
			}
			if calls.Load() != wantCalls {
				t.Fatalf("Portainer calls = %d, want %d", calls.Load(), wantCalls)
			}
		})
	}
}

func TestMachinePrincipalCarriesTokenScopes(t *testing.T) {
	manager, err := NewAuthManager(AuthConfig{
		Mode:          authModeOIDC,
		IssuerURL:     "http://127.0.0.1:1",
		ClientID:      "archview",
		SessionSecret: testSessionSecret,
	})
	if err != nil {
		t.Fatalf("NewAuthManager: %v", err)
	}

	principal, err := manager.principalFromMachineClaims(machineClaims(time.Now(), "http://127.0.0.1:1", "archview", "cron", "archview:read", "endpoints:admin"))
	if err != nil {
		t.Fatalf("principalFromMachineClaims: %v", err)
	}
	if !scopeContainsAll(principal.Scopes, []string{"endpoints:admin"}) {
		t.Fatalf("machine principal scopes = %v, want endpoints:admin", principal.Scopes)
	}
}

func captureLog(t *testing.T) *bytes.Buffer {
	t.Helper()
	var buffer bytes.Buffer
	previous := log.Writer()
	log.SetOutput(&buffer)
	t.Cleanup(func() { log.SetOutput(previous) })
	return &buffer
}

func TestPruneImagesAuditLineOnSuccess(t *testing.T) {
	logs := captureLog(t)
	portainer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`{"ImagesDeleted":[{"Deleted":"sha256:abc"},{"Untagged":"app:old"}],"SpaceReclaimed":123456}`))
	}))
	t.Cleanup(portainer.Close)

	server := newEndpointTestServer(t, portainer.URL, Config{
		Auth:                 endpointAdminTestAuth(),
		EndpointAdminClients: []string{"cron"},
	})
	principal := Principal{Name: "cron", Method: "client_credentials", Scopes: []string{"endpoints:admin"}}
	request := httptest.NewRequest(http.MethodPost, "https://archview.example/api/endpoints/rossmoney/prune-images?all=true", nil)
	request.Header.Set("Authorization", "Bearer super-secret-token")
	request = request.WithContext(context.WithValue(request.Context(), principalContextKey{}, principal))
	recorder := httptest.NewRecorder()

	server.handleEndpointRoute(recorder, request)

	if recorder.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200 (body %s)", recorder.Code, recorder.Body.String())
	}
	line := logs.String()
	for _, want := range []string{
		`endpoint="rossmoney"`,
		"portainerEndpointId=7",
		`principal="cron"`,
		`mode="all"`,
		"deleted 2 images",
		"reclaimed 123456 bytes",
	} {
		if !strings.Contains(line, want) {
			t.Fatalf("audit line %q does not contain %q", line, want)
		}
	}
	if strings.Contains(line, "super-secret-token") || strings.Contains(line, "Bearer") {
		t.Fatalf("audit line leaks the credential: %s", line)
	}
	if strings.Count(line, "prune-images endpoint=") != 1 {
		t.Fatalf("want exactly one audit line, got %d: %s", strings.Count(line, "prune-images endpoint="), line)
	}
}

func TestPruneImagesAuditLineOnRefusal(t *testing.T) {
	logs := captureLog(t)
	server := newEndpointTestServer(t, "https://portainer.example", Config{
		Auth:                 endpointAdminTestAuth(),
		EndpointAdminClients: []string{"cron"},
	})
	principal := Principal{Name: "cron", Method: "client_credentials", Scopes: []string{"archview:read"}}
	request := httptest.NewRequest(http.MethodPost, "https://archview.example/api/endpoints/rossmoney/prune-images", nil)
	request.Header.Set("Authorization", "Bearer super-secret-token")
	request = request.WithContext(context.WithValue(request.Context(), principalContextKey{}, principal))
	recorder := httptest.NewRecorder()

	server.handleEndpointRoute(recorder, request)

	if recorder.Code != http.StatusForbidden {
		t.Fatalf("status = %d, want 403 (body %s)", recorder.Code, recorder.Body.String())
	}
	line := logs.String()
	for _, want := range []string{
		`endpoint="rossmoney"`,
		`principal="cron"`,
		`mode="dangling"`,
		"refused:",
		"endpoints:admin",
	} {
		if !strings.Contains(line, want) {
			t.Fatalf("audit line %q does not contain %q", line, want)
		}
	}
	if strings.Contains(line, "super-secret-token") {
		t.Fatalf("audit line leaks the credential: %s", line)
	}
	if strings.Count(line, "prune-images endpoint=") != 1 {
		t.Fatalf("want exactly one audit line, got %d: %s", strings.Count(line, "prune-images endpoint="), line)
	}
}

func TestPruneImagesAuditLineRecordsUpstreamStatus(t *testing.T) {
	logs := captureLog(t)
	portainer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "portainer exploded", http.StatusInternalServerError)
	}))
	t.Cleanup(portainer.Close)

	server := newEndpointTestServer(t, portainer.URL, Config{
		Auth:                 endpointAdminTestAuth(),
		EndpointAdminClients: []string{"cron"},
	})
	principal := Principal{Name: "cron", Method: "client_credentials", Scopes: []string{"endpoints:admin"}}
	request := httptest.NewRequest(http.MethodPost, "https://archview.example/api/endpoints/rossmoney/prune-images", nil)
	request = request.WithContext(context.WithValue(request.Context(), principalContextKey{}, principal))
	recorder := httptest.NewRecorder()

	server.handleEndpointRoute(recorder, request)

	if recorder.Code != http.StatusBadGateway {
		t.Fatalf("status = %d, want 502 (body %s)", recorder.Code, recorder.Body.String())
	}
	line := logs.String()
	if !strings.Contains(line, "upstream status 500") {
		t.Fatalf("audit line %q does not record the upstream status", line)
	}
}
