package service

import (
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func TestNormalizeProjectAliases(t *testing.T) {
	cases := map[string]string{
		"travelling":   "travelling",
		"image-mosaic": "travelling",
		"photoprism":   "travelling",
		"rossmoney":    "rossmoney_me",
		"rossmoney-me": "rossmoney_me",
		"rossmoney_me": "rossmoney_me",
		"other":        "other",
	}
	for input, want := range cases {
		if got := normalizeProject(input); got != want {
			t.Errorf("normalizeProject(%q) = %q, want %q", input, got, want)
		}
	}
}

func TestCORSOnlyAllowsConfiguredOrigins(t *testing.T) {
	handler := newAuthServer(t, AuthConfig{Mode: authModeNone}, []string{"https://app.example"})

	allowed := httptest.NewRequest(http.MethodGet, "http://archview.test/healthz", nil)
	allowed.Header.Set("Origin", "https://app.example")
	recorder := httptest.NewRecorder()
	handler.ServeHTTP(recorder, allowed)
	if recorder.Header().Get("Access-Control-Allow-Origin") != "https://app.example" {
		t.Fatalf("allowed origin not echoed: %q", recorder.Header().Get("Access-Control-Allow-Origin"))
	}
	if recorder.Header().Get("Access-Control-Allow-Credentials") != "true" {
		t.Fatal("allowed origin should permit credentials")
	}
	if recorder.Header().Get("Vary") != "Origin" {
		t.Fatalf("missing Vary header: %q", recorder.Header().Get("Vary"))
	}

	disallowed := httptest.NewRequest(http.MethodGet, "http://archview.test/healthz", nil)
	disallowed.Header.Set("Origin", "https://evil.example")
	recorder = httptest.NewRecorder()
	handler.ServeHTTP(recorder, disallowed)
	if recorder.Header().Get("Access-Control-Allow-Origin") != "" {
		t.Fatal("disallowed origin must not receive CORS headers")
	}

	preflight := httptest.NewRequest(http.MethodOptions, "http://archview.test/api/system", nil)
	preflight.Header.Set("Origin", "https://app.example")
	preflight.Header.Set("Access-Control-Request-Method", "GET")
	recorder = httptest.NewRecorder()
	handler.ServeHTTP(recorder, preflight)
	if recorder.Code != http.StatusNoContent {
		t.Fatalf("preflight status = %d, want 204", recorder.Code)
	}
	if recorder.Header().Get("Access-Control-Allow-Methods") == "" {
		t.Fatal("preflight response is missing allowed methods")
	}
}

func TestCORSDefaultsToSameOriginOnly(t *testing.T) {
	handler := newAuthServer(t, AuthConfig{Mode: authModeNone}, nil)
	request := httptest.NewRequest(http.MethodGet, "http://archview.test/healthz", nil)
	request.Header.Set("Origin", "https://app.example")
	recorder := httptest.NewRecorder()
	handler.ServeHTTP(recorder, request)
	if recorder.Header().Get("Access-Control-Allow-Origin") != "" {
		t.Fatal("cross-origin access should be disabled by default")
	}
}

func TestReadyReportsProviderFailures(t *testing.T) {
	handler := newAuthServer(t, AuthConfig{
		Mode:          authModeOIDC,
		IssuerURL:     "http://127.0.0.1:1",
		ClientID:      testClientID,
		SessionSecret: testSessionSecret,
		HTTPTimeout:   time.Second,
	}, nil)

	recorder := httptest.NewRecorder()
	handler.ServeHTTP(recorder, httptest.NewRequest(http.MethodGet, "http://archview.test/readyz", nil))
	if recorder.Code != http.StatusServiceUnavailable {
		t.Fatalf("status = %d, want 503", recorder.Code)
	}
}

func TestLogoutClearsSessionCookie(t *testing.T) {
	handler := newAuthServer(t, AuthConfig{Mode: authModeNone}, nil)
	request := httptest.NewRequest(http.MethodGet, "http://archview.test/auth/logout", nil)
	request.AddCookie(&http.Cookie{Name: defaultSessionCookie, Value: "stale"})
	recorder := httptest.NewRecorder()
	handler.ServeHTTP(recorder, request)
	if recorder.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", recorder.Code)
	}
	cookie := cookieByName(recorder.Result().Cookies(), defaultSessionCookie)
	if cookie == nil || cookie.MaxAge >= 0 || cookie.Value != "" {
		t.Fatalf("session cookie was not cleared: %+v", cookie)
	}
}
