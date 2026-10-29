package service

import (
	"crypto/rsa"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"testing"
	"time"
)

const testClientID = "archview-test"

// fakeProvider is a minimal OIDC provider used by the end-to-end auth tests.
type fakeProvider struct {
	t      *testing.T
	server *httptest.Server
	key    *rsa.PrivateKey
	kid    string

	mu    sync.Mutex
	nonce string
	email string
}

func newFakeProvider(t *testing.T) *fakeProvider {
	t.Helper()
	provider := &fakeProvider{t: t, key: mustRSAKey(t), kid: "test-kid", email: "ross@example.com"}

	mux := http.NewServeMux()
	mux.HandleFunc("/.well-known/openid-configuration", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{
			"issuer":                 provider.server.URL,
			"authorization_endpoint": provider.server.URL + "/authorize",
			"token_endpoint":         provider.server.URL + "/token",
			"jwks_uri":               provider.server.URL + "/jwks",
			"userinfo_endpoint":      provider.server.URL + "/userinfo",
		})
	})
	mux.HandleFunc("/jwks", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{
			"keys": []any{rsaJWK(&provider.key.PublicKey, provider.kid)},
		})
	})
	mux.HandleFunc("/token", func(w http.ResponseWriter, r *http.Request) {
		if err := r.ParseForm(); err != nil {
			http.Error(w, "invalid form", http.StatusBadRequest)
			return
		}
		if r.Form.Get("code") != "test-code" ||
			r.Form.Get("grant_type") != "authorization_code" ||
			r.Form.Get("code_verifier") == "" {
			w.WriteHeader(http.StatusBadRequest)
			_ = json.NewEncoder(w).Encode(map[string]any{"error": "invalid_grant"})
			return
		}
		provider.mu.Lock()
		nonce, email := provider.nonce, provider.email
		provider.mu.Unlock()

		now := time.Now()
		idToken, err := signRS256Token(provider.key, provider.kid, map[string]any{
			"iss":   provider.server.URL,
			"aud":   testClientID,
			"sub":   "user-1",
			"email": email,
			"name":  "Ross",
			"nonce": nonce,
			"iat":   now.Unix(),
			"exp":   now.Add(time.Hour).Unix(),
		})
		if err != nil {
			http.Error(w, "signing failed", http.StatusInternalServerError)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{
			"access_token": "access-token",
			"token_type":   "Bearer",
			"id_token":     idToken,
			"expires_in":   3600,
		})
	})
	mux.HandleFunc("/userinfo", func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer access-token" {
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}
		provider.mu.Lock()
		email := provider.email
		provider.mu.Unlock()
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{
			"sub":   "user-1",
			"email": email,
			"name":  "Ross",
		})
	})

	provider.server = httptest.NewServer(mux)
	t.Cleanup(provider.server.Close)
	return provider
}

func (p *fakeProvider) setNonce(nonce string) {
	p.mu.Lock()
	p.nonce = nonce
	p.mu.Unlock()
}

func (p *fakeProvider) setEmail(email string) {
	p.mu.Lock()
	p.email = email
	p.mu.Unlock()
}

func testAuthConfig(providerURL string) AuthConfig {
	return AuthConfig{
		Mode:              authModeOIDC,
		IssuerURL:         providerURL,
		ClientID:          testClientID,
		ClientSecret:      "test-secret",
		RedirectURL:       "https://archview.test/auth/callback",
		Scopes:            []string{"openid", "profile", "email"},
		SessionSecret:     testSessionSecret,
		SessionTTL:        time.Hour,
		CookieSecure:      false,
		AllowedEmails:     []string{"ross@example.com"},
		PostLoginRedirect: "/",
	}
}

func newAuthServer(t *testing.T, cfg AuthConfig, cors []string) http.Handler {
	t.Helper()
	server, err := NewServer(Config{Auth: cfg, CORSOrigins: cors})
	if err != nil {
		t.Fatalf("NewServer: %v", err)
	}
	return server.Routes()
}

func cookieByName(cookies []*http.Cookie, name string) *http.Cookie {
	for _, cookie := range cookies {
		if cookie.Name == name {
			return cookie
		}
	}
	return nil
}

func startLogin(t *testing.T, handler http.Handler, target string) (authState, *http.Cookie, *url.URL) {
	t.Helper()
	request := httptest.NewRequest(http.MethodGet, "http://archview.test/auth/login?redirect="+url.QueryEscape(target), nil)
	recorder := httptest.NewRecorder()
	handler.ServeHTTP(recorder, request)
	if recorder.Code != http.StatusFound {
		t.Fatalf("login status = %d, want 302 (body %s)", recorder.Code, recorder.Body.String())
	}
	location, err := url.Parse(recorder.Header().Get("Location"))
	if err != nil {
		t.Fatalf("parse location: %v", err)
	}
	stateCookie := cookieByName(recorder.Result().Cookies(), stateCookieName)
	if stateCookie == nil {
		t.Fatal("state cookie was not set")
	}
	state, err := decodeAuthState(stateCookie.Value, testSessionSecret, time.Now())
	if err != nil {
		t.Fatalf("decode state cookie: %v", err)
	}
	return state, stateCookie, location
}

func completeCallback(t *testing.T, handler http.Handler, state authState, stateCookie *http.Cookie, code string) *httptest.ResponseRecorder {
	t.Helper()
	target := "http://archview.test/auth/callback?code=" + url.QueryEscape(code) + "&state=" + url.QueryEscape(state.State)
	request := httptest.NewRequest(http.MethodGet, target, nil)
	request.AddCookie(stateCookie)
	recorder := httptest.NewRecorder()
	handler.ServeHTTP(recorder, request)
	return recorder
}
func TestAuthMiddlewareProtectsApiOnly(t *testing.T) {
	provider := newFakeProvider(t)
	handler := newAuthServer(t, testAuthConfig(provider.server.URL), nil)

	public := []string{"/healthz", "/readyz", "/docs", "/docs/openapi.yaml", "/", "/auth/config", "/auth/login", "/auth/callback", "/auth/logout"}
	for _, path := range public {
		recorder := httptest.NewRecorder()
		handler.ServeHTTP(recorder, httptest.NewRequest(http.MethodGet, "http://archview.test"+path, nil))
		if recorder.Code == http.StatusUnauthorized || recorder.Code == http.StatusForbidden {
			t.Fatalf("%s should be public, got status %d", path, recorder.Code)
		}
	}

	recorder := httptest.NewRecorder()
	handler.ServeHTTP(recorder, httptest.NewRequest(http.MethodGet, "http://archview.test/api/system", nil))
	if recorder.Code != http.StatusUnauthorized {
		t.Fatalf("unauthenticated API status = %d, want 401", recorder.Code)
	}
	if recorder.Header().Get("WWW-Authenticate") == "" {
		t.Fatal("missing WWW-Authenticate header")
	}
	if recorder.Header().Get("Cache-Control") != "no-store" {
		t.Fatalf("API response should not be cached, got %q", recorder.Header().Get("Cache-Control"))
	}
}

func TestIndexIsJSONAndNotADashboard(t *testing.T) {
	handler := newAuthServer(t, AuthConfig{Mode: authModeNone}, nil)
	recorder := httptest.NewRecorder()
	handler.ServeHTTP(recorder, httptest.NewRequest(http.MethodGet, "http://archview.test/", nil))

	if recorder.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", recorder.Code)
	}
	if contentType := recorder.Header().Get("Content-Type"); !strings.HasPrefix(contentType, "application/json") {
		t.Fatalf("content type = %q, want application/json", contentType)
	}
	body := recorder.Body.String()
	if strings.Contains(strings.ToLower(body), "<!doctype html>") {
		t.Fatal("the dashboard should have been removed, but HTML was served")
	}
	var payload map[string]any
	if err := json.Unmarshal(recorder.Body.Bytes(), &payload); err != nil {
		t.Fatalf("decode index payload: %v", err)
	}
	if payload["service"] != "archview" {
		t.Fatalf("unexpected index payload: %s", body)
	}
	if recorder.Header().Get("X-Content-Type-Options") != "nosniff" {
		t.Fatal("security headers are missing")
	}
}

func TestLoginStartsPKCEFlow(t *testing.T) {
	provider := newFakeProvider(t)
	handler := newAuthServer(t, testAuthConfig(provider.server.URL), nil)

	state, stateCookie, location := startLogin(t, handler, "/docs")
	query := location.Query()

	if !strings.HasPrefix(location.String(), provider.server.URL+"/authorize") {
		t.Fatalf("unexpected authorization URL: %s", location)
	}
	if query.Get("response_type") != "code" {
		t.Fatalf("response_type = %q", query.Get("response_type"))
	}
	if query.Get("client_id") != testClientID {
		t.Fatalf("client_id = %q", query.Get("client_id"))
	}
	if query.Get("redirect_uri") != "https://archview.test/auth/callback" {
		t.Fatalf("redirect_uri = %q", query.Get("redirect_uri"))
	}
	if query.Get("code_challenge_method") != "S256" {
		t.Fatalf("code_challenge_method = %q", query.Get("code_challenge_method"))
	}
	if query.Get("code_challenge") != pkceChallenge(state.Verifier) {
		t.Fatal("code_challenge does not match the stored verifier")
	}
	if query.Get("state") != state.State {
		t.Fatal("state parameter does not match the state cookie")
	}
	if query.Get("nonce") != state.Nonce {
		t.Fatal("nonce parameter does not match the state cookie")
	}
	if state.Redirect != "/docs" {
		t.Fatalf("redirect = %q, want /docs", state.Redirect)
	}
	if !stateCookie.HttpOnly || stateCookie.Path != "/auth" {
		t.Fatalf("unexpected state cookie attributes: %+v", stateCookie)
	}
	if stateCookie.Secure {
		t.Fatal("state cookie should follow CookieSecure=false in tests")
	}
}

func TestCallbackIssuesSessionAndUnlocksApi(t *testing.T) {
	provider := newFakeProvider(t)
	handler := newAuthServer(t, testAuthConfig(provider.server.URL), nil)

	state, stateCookie, _ := startLogin(t, handler, "/docs")
	provider.setNonce(state.Nonce)

	recorder := completeCallback(t, handler, state, stateCookie, "test-code")
	if recorder.Code != http.StatusFound {
		t.Fatalf("callback status = %d, want 302 (body %s)", recorder.Code, recorder.Body.String())
	}
	if location := recorder.Header().Get("Location"); location != "/docs" {
		t.Fatalf("redirect = %q, want /docs", location)
	}
	sessionCookie := cookieByName(recorder.Result().Cookies(), defaultSessionCookie)
	if sessionCookie == nil {
		t.Fatal("session cookie was not set")
	}
	if !sessionCookie.HttpOnly {
		t.Fatal("session cookie must be HttpOnly")
	}

	userRecorder := httptest.NewRecorder()
	userRequest := httptest.NewRequest(http.MethodGet, "http://archview.test/auth/user", nil)
	userRequest.AddCookie(sessionCookie)
	handler.ServeHTTP(userRecorder, userRequest)
	if userRecorder.Code != http.StatusOK {
		t.Fatalf("auth/user status = %d", userRecorder.Code)
	}
	var userPayload struct {
		Authenticated bool `json:"authenticated"`
		User          struct {
			Email string `json:"email"`
		} `json:"user"`
	}
	if err := json.Unmarshal(userRecorder.Body.Bytes(), &userPayload); err != nil {
		t.Fatalf("decode auth/user payload: %v", err)
	}
	if !userPayload.Authenticated {
		t.Fatalf("unexpected auth/user payload: %s", userRecorder.Body.String())
	}
	if userPayload.User.Email != "ross@example.com" {
		t.Fatalf("session principal is missing the email: %s", userRecorder.Body.String())
	}

	apiRecorder := httptest.NewRecorder()
	apiRequest := httptest.NewRequest(http.MethodGet, "http://archview.test/api/system", nil)
	apiRequest.AddCookie(sessionCookie)
	handler.ServeHTTP(apiRecorder, apiRequest)
	if apiRecorder.Code != http.StatusOK {
		t.Fatalf("authenticated API status = %d, want 200", apiRecorder.Code)
	}
}

func TestCallbackRejectsInvalidState(t *testing.T) {
	provider := newFakeProvider(t)
	handler := newAuthServer(t, testAuthConfig(provider.server.URL), nil)

	state, stateCookie, _ := startLogin(t, handler, "/")
	state.State = state.State + "tampered"
	recorder := completeCallback(t, handler, state, stateCookie, "test-code")
	if recorder.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400", recorder.Code)
	}

	missingCookie := httptest.NewRecorder()
	missingCookieRequest := httptest.NewRequest(http.MethodGet, "http://archview.test/auth/callback?code=test-code&state="+state.State, nil)
	handler.ServeHTTP(missingCookie, missingCookieRequest)
	if missingCookie.Code != http.StatusBadRequest {
		t.Fatalf("missing state cookie status = %d, want 400", missingCookie.Code)
	}
}

func TestCallbackRejectsDisallowedEmailAndNonce(t *testing.T) {
	provider := newFakeProvider(t)
	handler := newAuthServer(t, testAuthConfig(provider.server.URL), nil)

	state, stateCookie, _ := startLogin(t, handler, "/")
	provider.setNonce(state.Nonce)
	provider.setEmail("intruder@evil.example")
	recorder := completeCallback(t, handler, state, stateCookie, "test-code")
	if recorder.Code != http.StatusForbidden {
		t.Fatalf("status = %d, want 403 (body %s)", recorder.Code, recorder.Body.String())
	}

	provider.setEmail("ross@example.com")
	provider.setNonce("different-nonce")
	recorder = completeCallback(t, handler, state, stateCookie, "test-code")
	if recorder.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d, want 401 (body %s)", recorder.Code, recorder.Body.String())
	}
}

func TestBearerJWTAndAPIKeyAuthentication(t *testing.T) {
	provider := newFakeProvider(t)
	config := testAuthConfig(provider.server.URL)
	config.APIKeys = []string{"monitor:static-api-key"}
	handler := newAuthServer(t, config, nil)

	now := time.Now()
	claims := validClaims(now, provider.server.URL, testClientID)
	claims["sub"] = "service-user"
	token := signRS256(t, provider.key, provider.kid, claims)

	apiRequest := httptest.NewRequest(http.MethodGet, "http://archview.test/api/system", nil)
	apiRequest.Header.Set("Authorization", "Bearer "+token)
	recorder := httptest.NewRecorder()
	handler.ServeHTTP(recorder, apiRequest)
	if recorder.Code != http.StatusOK {
		t.Fatalf("bearer token status = %d, want 200 (body %s)", recorder.Code, recorder.Body.String())
	}

	apiKeyRequest := httptest.NewRequest(http.MethodGet, "http://archview.test/api/system", nil)
	apiKeyRequest.Header.Set("Authorization", "Bearer static-api-key")
	recorder = httptest.NewRecorder()
	handler.ServeHTTP(recorder, apiKeyRequest)
	if recorder.Code != http.StatusOK {
		t.Fatalf("api key status = %d, want 200", recorder.Code)
	}

	userRequest := httptest.NewRequest(http.MethodGet, "http://archview.test/auth/user", nil)
	userRequest.Header.Set("Authorization", "Bearer static-api-key")
	recorder = httptest.NewRecorder()
	handler.ServeHTTP(recorder, userRequest)
	if !strings.Contains(recorder.Body.String(), "api_key") {
		t.Fatalf("api key principal not reported: %s", recorder.Body.String())
	}
	if strings.Contains(recorder.Body.String(), "static-api-key") {
		t.Fatal("the raw API key must never be returned to clients")
	}

	expired := validClaims(now.Add(-3*time.Hour), provider.server.URL, testClientID)
	expiredRequest := httptest.NewRequest(http.MethodGet, "http://archview.test/api/system", nil)
	expiredRequest.Header.Set("Authorization", "Bearer "+signRS256(t, provider.key, provider.kid, expired))
	recorder = httptest.NewRecorder()
	handler.ServeHTTP(recorder, expiredRequest)
	if recorder.Code != http.StatusUnauthorized {
		t.Fatalf("expired token status = %d, want 401", recorder.Code)
	}
}

func TestAPIKeyOnlyModeNeedsNoProviderOrSessionSecret(t *testing.T) {
	handler := newAuthServer(t, AuthConfig{
		Mode:    authModeNone,
		APIKeys: []string{"monitor-key"},
	}, nil)

	recorder := httptest.NewRecorder()
	handler.ServeHTTP(recorder, httptest.NewRequest(http.MethodGet, "http://archview.test/api/system", nil))
	if recorder.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d, want 401", recorder.Code)
	}

	request := httptest.NewRequest(http.MethodGet, "http://archview.test/api/system", nil)
	request.Header.Set("Authorization", "Bearer monitor-key")
	recorder = httptest.NewRecorder()
	handler.ServeHTTP(recorder, request)
	if recorder.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", recorder.Code)
	}
}

func TestAuthConfigAndJSONLogin(t *testing.T) {
	provider := newFakeProvider(t)
	handler := newAuthServer(t, testAuthConfig(provider.server.URL), nil)

	recorder := httptest.NewRecorder()
	handler.ServeHTTP(recorder, httptest.NewRequest(http.MethodGet, "http://archview.test/auth/config", nil))
	if recorder.Code != http.StatusOK {
		t.Fatalf("auth/config status = %d", recorder.Code)
	}
	var configPayload map[string]any
	if err := json.Unmarshal(recorder.Body.Bytes(), &configPayload); err != nil {
		t.Fatalf("decode auth/config payload: %v", err)
	}
	if configPayload["loginUrl"] != "/auth/login" {
		t.Fatalf("unexpected auth/config payload: %s", recorder.Body.String())
	}

	request := httptest.NewRequest(http.MethodGet, "http://archview.test/auth/login?format=json&redirect=/docs", nil)
	recorder = httptest.NewRecorder()
	handler.ServeHTTP(recorder, request)
	if recorder.Code != http.StatusOK {
		t.Fatalf("json login status = %d (body %s)", recorder.Code, recorder.Body.String())
	}
	var loginPayload map[string]any
	if err := json.Unmarshal(recorder.Body.Bytes(), &loginPayload); err != nil {
		t.Fatalf("decode login payload: %v", err)
	}
	if loginPayload["authorizationUrl"] == "" {
		t.Fatalf("unexpected json login payload: %s", recorder.Body.String())
	}
}

func TestSafeRedirectRejectsOpenRedirects(t *testing.T) {
	manager, err := NewAuthManager(AuthConfig{
		Mode:                authModeOIDC,
		IssuerURL:           testIssuer,
		ClientID:            testClientID,
		SessionSecret:       testSessionSecret,
		AllowedRedirectURLs: []string{"https://app.example/after"},
		PostLoginRedirect:   "/",
	})
	if err != nil {
		t.Fatalf("NewAuthManager: %v", err)
	}

	request := httptest.NewRequest(http.MethodGet, "https://archview.example/auth/login", nil)
	cases := map[string]string{
		"/docs":                       "/docs",
		"//evil.example":              "/",
		"https://evil.example/steal":  "/",
		"https://archview.example/ok": "https://archview.example/ok",
		"https://app.example/after/1": "https://app.example/after/1",
		"https://app.example/other":   "/",
	}
	for input, want := range cases {
		if got := manager.safeRedirect(request, input); got != want {
			t.Fatalf("safeRedirect(%q) = %q, want %q", input, got, want)
		}
	}
}

func TestCheckAllowedDomains(t *testing.T) {
	manager, err := NewAuthManager(AuthConfig{
		Mode:           authModeOIDC,
		IssuerURL:      testIssuer,
		ClientID:       testClientID,
		SessionSecret:  testSessionSecret,
		AllowedDomains: []string{"example.com"},
	})
	if err != nil {
		t.Fatalf("NewAuthManager: %v", err)
	}

	allowed := []string{"ross@example.com", "team@eng.example.com"}
	for _, email := range allowed {
		if err := manager.checkAllowed(Principal{Email: email}); err != nil {
			t.Fatalf("%q should be allowed: %v", email, err)
		}
	}
	denied := []string{"ross@evil-example.com", "ross@example.com.evil.example", ""}
	for _, email := range denied {
		if err := manager.checkAllowed(Principal{Email: email}); err == nil {
			t.Fatalf("%q should be denied", email)
		}
	}
}

func TestNewServerValidatesAuthConfiguration(t *testing.T) {
	cases := []AuthConfig{
		{Mode: authModeOIDC, IssuerURL: testIssuer},                                      // no client ID or secret
		{Mode: authModeOIDC, IssuerURL: testIssuer, ClientID: testClientID},              // short secret
		{Mode: authModeOIDC, ClientID: testClientID, SessionSecret: testSessionSecret},   // no issuer
		{Mode: authModeOAuth2, ClientID: testClientID, SessionSecret: testSessionSecret}, // no endpoints
		{
			Mode:           authModeOIDC,
			IssuerURL:      testIssuer,
			ClientID:       testClientID,
			SessionSecret:  testSessionSecret,
			CookieSameSite: "none",
			CookieSecure:   false, // SameSite=None requires Secure cookies
		},
		{
			Mode:              authModeOIDC,
			IssuerURL:         testIssuer,
			ClientID:          testClientID,
			SessionSecret:     testSessionSecret,
			PostLoginRedirect: "javascript:alert(1)",
		},
	}
	for _, cfg := range cases {
		if _, err := NewServer(Config{Auth: cfg}); err == nil {
			t.Fatalf("expected configuration %+v to be rejected", cfg)
		}
	}
}
