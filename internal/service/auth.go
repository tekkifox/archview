package service

import (
	"context"
	"crypto/rand"
	"crypto/subtle"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"
)

const (
	authModeNone   = "none"
	authModeOIDC   = "oidc"
	authModeOAuth2 = "oauth2"

	defaultSessionCookie = "archview_session"
	stateCookieName      = "archview_oauth_state"
	stateTTL             = 10 * time.Minute
	providerCacheTTL     = 15 * time.Minute
)

var (
	errNotAuthenticated = errors.New("not authenticated")
	errNotAllowed       = errors.New("account is not allowed to access this service")
)

// AuthConfig configures OAuth/OIDC login and API authentication.
//
// The API accepts three kinds of credentials:
//   - a signed session cookie created by the OAuth login flow,
//   - a static API key (see APIKeys) for service-to-service calls,
//   - an OIDC bearer token validated against the provider's JWKS.
type AuthConfig struct {
	// Mode is "none", "oidc" or "oauth2". When empty it is inferred from the
	// configured endpoints. "oauth2" is for providers without OIDC discovery,
	// such as GitHub.
	Mode string

	IssuerURL    string
	DiscoveryURL string

	AuthorizationURL string
	TokenURL         string
	UserinfoURL      string
	EmailsURL        string
	JWKSURL          string
	EndSessionURL    string

	ClientID     string
	ClientSecret string
	RedirectURL  string
	Scopes       []string

	// TokenAuthMethod is "client_secret_basic", "client_secret_post" or
	// "none". Defaults to client_secret_basic when a secret is configured.
	TokenAuthMethod string

	// Claim names used to build the principal. Defaults are the OIDC standard
	// claims; override them for non-OIDC providers.
	SubjectClaim string
	EmailClaim   string
	NameClaim    string
	PictureClaim string

	// AllowedEmails and AllowedDomains restrict who may log in. When both are
	// empty any identity accepted by the provider may use the API.
	AllowedEmails  []string
	AllowedDomains []string

	// Audiences are the accepted `aud` values for bearer JWTs. Defaults to the
	// client ID.
	Audiences []string

	// APIKeys are static bearer tokens for machine-to-machine access. Entries
	// may be labelled as "label:key"; the label is reported in the principal
	// but never the key itself.
	APIKeys []string

	// SessionSecret signs the session cookie (HMAC-SHA256). It must be at least
	// 32 bytes and identical across replicas.
	SessionSecret []byte
	SessionTTL    time.Duration
	CookieName    string
	CookieDomain  string
	// CookieSameSite is "lax", "strict" or "none". Use "none" (with
	// CookieSecure=true) only when a browser frontend is hosted on a different
	// site and calls the API with credentials.
	CookieSameSite string
	// CookieSecure should stay true in production. Set it to false only for
	// plain-HTTP development.
	CookieSecure bool

	PostLoginRedirect   string
	PostLogoutRedirect  string
	AllowedRedirectURLs []string

	// AllowInsecureHTTP permits http:// identity provider endpoints. It is
	// intended for local development or an internal IdP on a trusted network.
	AllowInsecureHTTP bool
	// TrustProxyHeaders honours X-Forwarded-Proto/Host when building the
	// OAuth redirect URL. Only enable it behind a trusted reverse proxy.
	TrustProxyHeaders bool

	HTTPTimeout time.Duration
}

type apiKey struct {
	label string
	value string
}

type providerMetadata struct {
	Issuer                string `json:"issuer"`
	AuthorizationEndpoint string `json:"authorization_endpoint"`
	TokenEndpoint         string `json:"token_endpoint"`
	JWKSURI               string `json:"jwks_uri"`
	UserinfoEndpoint      string `json:"userinfo_endpoint"`
	EndSessionEndpoint    string `json:"end_session_endpoint"`
}

// AuthManager owns the OAuth/OIDC client, the JWKS cache and request
// authentication. It holds no per-user state, so any number of replicas can
// share the same SESSION_SECRET and serve the same sessions.
type AuthManager struct {
	cfg       AuthConfig
	client    *http.Client
	apiKeys   []apiKey
	scopes    []string
	audiences []string

	mu         sync.Mutex
	metadata   providerMetadata
	metadataAt time.Time
	jwks       *jwksCache
}

// NewAuthManager validates the configuration and returns a ready manager.
func NewAuthManager(cfg AuthConfig) (*AuthManager, error) {
	cfg.Mode = strings.ToLower(strings.TrimSpace(cfg.Mode))
	if cfg.Mode == "" {
		switch {
		case cfg.IssuerURL != "" || cfg.DiscoveryURL != "":
			cfg.Mode = authModeOIDC
		case cfg.AuthorizationURL != "" && cfg.TokenURL != "":
			cfg.Mode = authModeOAuth2
		default:
			cfg.Mode = authModeNone
		}
	}
	switch cfg.Mode {
	case authModeNone, authModeOIDC, authModeOAuth2:
	default:
		return nil, fmt.Errorf("unsupported AUTH_MODE %q (want none, oidc or oauth2)", cfg.Mode)
	}

	if cfg.CookieName == "" {
		cfg.CookieName = defaultSessionCookie
	}
	cfg.CookieSameSite = strings.ToLower(strings.TrimSpace(cfg.CookieSameSite))
	if cfg.CookieSameSite == "" {
		cfg.CookieSameSite = "lax"
	}
	switch cfg.CookieSameSite {
	case "lax", "strict", "none":
	default:
		return nil, fmt.Errorf("unsupported SESSION_COOKIE_SAMESITE %q (want lax, strict or none)", cfg.CookieSameSite)
	}
	if cfg.CookieSameSite == "none" && !cfg.CookieSecure {
		return nil, errors.New("SESSION_COOKIE_SAMESITE=none requires SESSION_COOKIE_SECURE=true")
	}
	if cfg.SessionTTL <= 0 {
		cfg.SessionTTL = 8 * time.Hour
	}
	if cfg.SessionTTL > 30*24*time.Hour {
		return nil, errors.New("SESSION_TTL must not exceed 720h")
	}
	if cfg.PostLoginRedirect == "" {
		cfg.PostLoginRedirect = "/"
	}
	if err := validateRedirectURL("OAUTH_POST_LOGIN_REDIRECT", cfg.PostLoginRedirect); err != nil {
		return nil, err
	}
	if err := validateRedirectURL("OAUTH_POST_LOGOUT_REDIRECT", cfg.PostLogoutRedirect); err != nil {
		return nil, err
	}
	for _, allowed := range cfg.AllowedRedirectURLs {
		if err := validateRedirectURL("OAUTH_ALLOWED_REDIRECT_URLS", allowed); err != nil {
			return nil, err
		}
	}
	if cfg.SubjectClaim == "" {
		cfg.SubjectClaim = "sub"
	}
	if cfg.EmailClaim == "" {
		cfg.EmailClaim = "email"
	}
	if cfg.NameClaim == "" {
		cfg.NameClaim = "name"
	}
	if cfg.PictureClaim == "" {
		cfg.PictureClaim = "picture"
	}
	if cfg.HTTPTimeout <= 0 {
		cfg.HTTPTimeout = 10 * time.Second
	}
	if cfg.TokenAuthMethod == "" {
		if cfg.ClientSecret != "" {
			cfg.TokenAuthMethod = "client_secret_basic"
		} else {
			cfg.TokenAuthMethod = "none"
		}
	}
	switch cfg.TokenAuthMethod {
	case "client_secret_basic", "client_secret_post", "none":
	default:
		return nil, fmt.Errorf("unsupported OAUTH_TOKEN_AUTH_METHOD %q", cfg.TokenAuthMethod)
	}

	if cfg.Mode != authModeNone {
		if cfg.ClientID == "" {
			return nil, errors.New("OAUTH_CLIENT_ID is required when authentication is enabled")
		}
		if len(cfg.SessionSecret) < 32 {
			return nil, errors.New("SESSION_SECRET must be at least 32 bytes when authentication is enabled")
		}
		if cfg.Mode == authModeOIDC && cfg.IssuerURL == "" && cfg.DiscoveryURL == "" {
			return nil, errors.New("OAUTH_ISSUER or OAUTH_DISCOVERY_URL is required for AUTH_MODE=oidc")
		}
		if cfg.Mode == authModeOAuth2 {
			if cfg.AuthorizationURL == "" || cfg.TokenURL == "" {
				return nil, errors.New("OAUTH_AUTHORIZATION_URL and OAUTH_TOKEN_URL are required for AUTH_MODE=oauth2")
			}
			if cfg.UserinfoURL == "" && cfg.JWKSURL == "" {
				return nil, errors.New("OAUTH_USERINFO_URL is required for AUTH_MODE=oauth2")
			}
		}
		for name, raw := range map[string]string{
			"OAUTH_ISSUER":            cfg.IssuerURL,
			"OAUTH_DISCOVERY_URL":     cfg.DiscoveryURL,
			"OAUTH_AUTHORIZATION_URL": cfg.AuthorizationURL,
			"OAUTH_TOKEN_URL":         cfg.TokenURL,
			"OAUTH_USERINFO_URL":      cfg.UserinfoURL,
			"OAUTH_EMAILS_URL":        cfg.EmailsURL,
			"OAUTH_JWKS_URL":          cfg.JWKSURL,
			"OAUTH_REDIRECT_URL":      cfg.RedirectURL,
		} {
			if err := validateAuthURL(name, raw, cfg.AllowInsecureHTTP); err != nil {
				return nil, err
			}
		}
	}

	manager := &AuthManager{
		cfg:     cfg,
		client:  &http.Client{Timeout: cfg.HTTPTimeout},
		apiKeys: parseAPIKeys(cfg.APIKeys),
		scopes:  cfg.Scopes,
	}
	if len(manager.scopes) == 0 && cfg.Mode == authModeOIDC {
		manager.scopes = []string{"openid", "profile", "email"}
	}
	manager.audiences = cfg.Audiences
	if len(manager.audiences) == 0 && cfg.Mode != authModeNone {
		manager.audiences = []string{cfg.ClientID}
	}

	if cfg.Mode != authModeNone {
		log.Printf("archview auth: requesting oauth scopes: %s", strings.Join(manager.scopes, " "))
		for _, scope := range manager.scopes {
			// Catches the two most common env mistakes: an email address pasted
			// into OAUTH_SCOPES, and two variables merged onto one line.
			if strings.ContainsAny(scope, "@=") {
				log.Printf("archview auth: WARNING: OAUTH_SCOPES entry %q does not look like a scope; put address allowlists in OAUTH_ALLOWED_EMAILS and keep each variable on its own line", scope)
			}
		}
	}
	return manager, nil
}

func parseAPIKeys(raw []string) []apiKey {
	keys := make([]apiKey, 0, len(raw))
	for _, entry := range raw {
		entry = strings.TrimSpace(entry)
		if entry == "" {
			continue
		}
		label := "api-key"
		value := entry
		if name, key, ok := strings.Cut(entry, ":"); ok && strings.TrimSpace(name) != "" && strings.TrimSpace(key) != "" {
			label = strings.TrimSpace(name)
			value = strings.TrimSpace(key)
		}
		keys = append(keys, apiKey{label: label, value: value})
	}
	return keys
}

func validateAuthURL(name, raw string, allowInsecure bool) error {
	if raw == "" {
		return nil
	}
	parsed, err := url.Parse(raw)
	if err != nil {
		return fmt.Errorf("%s is not a valid URL: %w", name, err)
	}
	if parsed.Scheme != "http" && parsed.Scheme != "https" {
		return fmt.Errorf("%s must use http or https", name)
	}
	if parsed.Host == "" {
		return fmt.Errorf("%s must include a host", name)
	}
	if parsed.Scheme == "http" && !allowInsecure && !isLoopbackHost(parsed.Hostname()) {
		return fmt.Errorf("%s must use https (set OAUTH_ALLOW_INSECURE_HTTP=true only for trusted networks)", name)
	}
	return nil
}

func isLoopbackHost(host string) bool {
	switch strings.ToLower(host) {
	case "localhost", "127.0.0.1", "::1", "[::1]":
		return true
	default:
		return false
	}
}

// validateRedirectURL rejects unsafe redirect targets such as javascript: URLs.
// Relative paths and absolute http(s) URLs are accepted.
func validateRedirectURL(name, value string) error {
	value = strings.TrimSpace(value)
	if value == "" {
		return nil
	}
	if strings.HasPrefix(value, "/") {
		if strings.HasPrefix(value, "//") {
			return fmt.Errorf("%s must not be a protocol-relative URL", name)
		}
		return nil
	}
	parsed, err := url.Parse(value)
	if err != nil {
		return fmt.Errorf("%s is not a valid URL: %w", name, err)
	}
	if (parsed.Scheme != "http" && parsed.Scheme != "https") || parsed.Host == "" {
		return fmt.Errorf("%s must be a relative path or an absolute http(s) URL", name)
	}
	return nil
}

// Enabled reports whether requests must present credentials.
func (a *AuthManager) Enabled() bool {
	return a.cfg.Mode != authModeNone || len(a.apiKeys) > 0
}

// PublicInfo is safe to expose to unauthenticated clients and lets a frontend
// discover how to start the login flow.
func (a *AuthManager) PublicInfo() map[string]any {
	info := map[string]any{
		"enabled": a.Enabled(),
		"mode":    a.cfg.Mode,
	}
	if a.cfg.Mode != authModeNone {
		info["loginUrl"] = "/auth/login"
		info["logoutUrl"] = "/auth/logout"
		info["userUrl"] = "/auth/user"
	}
	return info
}

// Ready verifies that the identity provider can be reached and that the
// endpoints required by the selected mode are present.
func (a *AuthManager) Ready(ctx context.Context) error {
	if a.cfg.Mode == authModeNone {
		return nil
	}
	md, err := a.provider(ctx)
	if err != nil {
		return err
	}
	if a.cfg.Mode == authModeOIDC && md.JWKSURI == "" {
		return errors.New("identity provider does not expose a jwks_uri")
	}
	if md.AuthorizationEndpoint == "" || md.TokenEndpoint == "" {
		return errors.New("identity provider metadata is incomplete")
	}
	return nil
}

func (a *AuthManager) provider(ctx context.Context) (providerMetadata, error) {
	a.mu.Lock()
	if !a.metadataAt.IsZero() && time.Since(a.metadataAt) < providerCacheTTL && a.metadata.TokenEndpoint != "" {
		md := a.metadata
		a.mu.Unlock()
		return md, nil
	}
	a.mu.Unlock()

	md, err := a.discover(ctx)
	if err != nil {
		return providerMetadata{}, err
	}

	a.mu.Lock()
	a.metadata = md
	a.metadataAt = time.Now()
	if md.JWKSURI != "" && (a.jwks == nil || a.jwks.url != md.JWKSURI) {
		a.jwks = newJWKSCache(md.JWKSURI, a.client)
	}
	a.mu.Unlock()
	return md, nil
}

func (a *AuthManager) discover(ctx context.Context) (providerMetadata, error) {
	md := providerMetadata{
		Issuer:                a.cfg.IssuerURL,
		AuthorizationEndpoint: a.cfg.AuthorizationURL,
		TokenEndpoint:         a.cfg.TokenURL,
		JWKSURI:               a.cfg.JWKSURL,
		UserinfoEndpoint:      a.cfg.UserinfoURL,
		EndSessionEndpoint:    a.cfg.EndSessionURL,
	}

	discoveryURL := a.cfg.DiscoveryURL
	if discoveryURL == "" && a.cfg.IssuerURL != "" {
		discoveryURL = strings.TrimRight(a.cfg.IssuerURL, "/") + "/.well-known/openid-configuration"
	}
	if discoveryURL != "" {
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, discoveryURL, nil)
		if err != nil {
			return providerMetadata{}, err
		}
		req.Header.Set("Accept", "application/json")
		req.Header.Set("User-Agent", requestUserAgent)
		resp, err := a.client.Do(req)
		if err != nil {
			return providerMetadata{}, fmt.Errorf("openid discovery failed: %w", err)
		}
		defer resp.Body.Close()
		if resp.StatusCode != http.StatusOK {
			return providerMetadata{}, fmt.Errorf("openid discovery failed: unexpected status %d", resp.StatusCode)
		}
		var remote providerMetadata
		if err := json.NewDecoder(io.LimitReader(resp.Body, maxJWKSResponse)).Decode(&remote); err != nil {
			return providerMetadata{}, fmt.Errorf("openid discovery failed: %w", err)
		}
		if a.cfg.IssuerURL != "" && remote.Issuer != "" && remote.Issuer != a.cfg.IssuerURL {
			return providerMetadata{}, fmt.Errorf("openid discovery issuer mismatch: got %q", remote.Issuer)
		}
		// Explicit configuration always wins over discovered values.
		if md.Issuer == "" {
			md.Issuer = remote.Issuer
		}
		if md.AuthorizationEndpoint == "" {
			md.AuthorizationEndpoint = remote.AuthorizationEndpoint
		}
		if md.TokenEndpoint == "" {
			md.TokenEndpoint = remote.TokenEndpoint
		}
		if md.JWKSURI == "" {
			md.JWKSURI = remote.JWKSURI
		}
		if md.UserinfoEndpoint == "" {
			md.UserinfoEndpoint = remote.UserinfoEndpoint
		}
		if md.EndSessionEndpoint == "" {
			md.EndSessionEndpoint = remote.EndSessionEndpoint
		}
	}

	for name, raw := range map[string]string{
		"authorization_endpoint": md.AuthorizationEndpoint,
		"token_endpoint":         md.TokenEndpoint,
		"userinfo_endpoint":      md.UserinfoEndpoint,
		"jwks_uri":               md.JWKSURI,
		"end_session_endpoint":   md.EndSessionEndpoint,
		"issuer":                 md.Issuer,
	} {
		if err := validateAuthURL(name, raw, a.cfg.AllowInsecureHTTP); err != nil {
			return providerMetadata{}, err
		}
	}
	if md.AuthorizationEndpoint == "" || md.TokenEndpoint == "" {
		return providerMetadata{}, errors.New("identity provider metadata is missing the authorization or token endpoint")
	}
	if a.cfg.Mode == authModeOIDC && md.JWKSURI == "" {
		return providerMetadata{}, errors.New("identity provider metadata is missing jwks_uri")
	}
	if a.cfg.Mode == authModeOAuth2 && md.UserinfoEndpoint == "" && md.JWKSURI == "" {
		return providerMetadata{}, errors.New("identity provider metadata is missing userinfo_endpoint")
	}
	return md, nil
}

// authState is the short lived payload carried in the OAuth state cookie. The
// cookie is signed with the same secret as the session cookie, which provides
// CSRF protection for the callback.
type authState struct {
	State       string `json:"state"`
	Verifier    string `json:"verifier"`
	Nonce       string `json:"nonce"`
	Redirect    string `json:"redirect"`
	RedirectURI string `json:"redirect_uri"`
	Mode        string `json:"mode,omitempty"`
	ExpiresAt   int64  `json:"exp"`
}

func newRandomToken(size int) (string, error) {
	buffer := make([]byte, size)
	if _, err := rand.Read(buffer); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(buffer), nil
}

func encodeAuthState(state authState, secret []byte) (string, error) {
	payload, err := json.Marshal(state)
	if err != nil {
		return "", err
	}
	return signToken(payload, secret), nil
}

func decodeAuthState(raw string, secret []byte, now time.Time) (authState, error) {
	payload, err := verifyToken(raw, secret)
	if err != nil {
		return authState{}, err
	}
	var state authState
	if err := json.Unmarshal(payload, &state); err != nil {
		return authState{}, err
	}
	if state.State == "" || state.Verifier == "" || state.RedirectURI == "" {
		return authState{}, errors.New("incomplete oauth state cookie")
	}
	if state.ExpiresAt <= now.Unix() {
		return authState{}, errors.New("oauth state expired")
	}
	return state, nil
}

func (a *AuthManager) sameSite() http.SameSite {
	switch a.cfg.CookieSameSite {
	case "strict":
		return http.SameSiteStrictMode
	case "none":
		return http.SameSiteNoneMode
	default:
		return http.SameSiteLaxMode
	}
}

func (a *AuthManager) stateCookie(value string, maxAge int) *http.Cookie {
	return &http.Cookie{
		Name:     stateCookieName,
		Value:    value,
		Path:     "/auth",
		MaxAge:   maxAge,
		HttpOnly: true,
		Secure:   a.cfg.CookieSecure,
		SameSite: a.sameSite(),
	}
}

func (a *AuthManager) sessionCookie(value string, expires time.Time) *http.Cookie {
	cookie := &http.Cookie{
		Name:     a.cfg.CookieName,
		Value:    value,
		Path:     "/",
		Expires:  expires,
		HttpOnly: true,
		Secure:   a.cfg.CookieSecure,
		SameSite: a.sameSite(),
		Domain:   a.cfg.CookieDomain,
	}
	if maxAge := int(time.Until(expires).Seconds()); maxAge > 0 {
		cookie.MaxAge = maxAge
	}
	return cookie
}

func (a *AuthManager) clearCookie(w http.ResponseWriter, cookie *http.Cookie) {
	cookie.Value = ""
	cookie.MaxAge = -1
	cookie.Expires = time.Unix(0, 0)
	http.SetCookie(w, cookie)
}

// redirectURL returns the OAuth callback URL. Deployments behind a proxy should
// set OAUTH_REDIRECT_URL (recommended) or enable TRUST_PROXY_HEADERS.
func (a *AuthManager) redirectURL(r *http.Request) string {
	if a.cfg.RedirectURL != "" {
		return a.cfg.RedirectURL
	}
	scheme := "http"
	if r.TLS != nil {
		scheme = "https"
	}
	host := r.Host
	if a.cfg.TrustProxyHeaders {
		if forwarded := firstHeaderValue(r.Header.Get("X-Forwarded-Proto")); forwarded != "" {
			scheme = forwarded
		}
		if forwarded := firstHeaderValue(r.Header.Get("X-Forwarded-Host")); forwarded != "" {
			host = forwarded
		}
	}
	if host == "" {
		host = "localhost"
	}
	return scheme + "://" + host + "/auth/callback"
}

func firstHeaderValue(value string) string {
	first, _, _ := strings.Cut(value, ",")
	return strings.TrimSpace(first)
}

// safeRedirect prevents open redirects. Relative paths and URLs explicitly
// allowlisted through OAUTH_ALLOWED_REDIRECT_URLS are accepted.
func (a *AuthManager) safeRedirect(r *http.Request, target string) string {
	fallback := a.cfg.PostLoginRedirect
	target = strings.TrimSpace(target)
	if target == "" {
		return fallback
	}
	if strings.HasPrefix(target, "/") && !strings.HasPrefix(target, "//") && !strings.Contains(target, "\\") {
		return target
	}
	parsed, err := url.Parse(target)
	if err != nil || parsed.Host == "" || (parsed.Scheme != "http" && parsed.Scheme != "https") {
		return fallback
	}
	if strings.EqualFold(parsed.Host, r.Host) && strings.EqualFold(parsed.Scheme, requestScheme(r)) {
		return target
	}
	for _, allowed := range a.cfg.AllowedRedirectURLs {
		candidate, err := url.Parse(strings.TrimSpace(allowed))
		if err != nil || candidate.Host == "" {
			continue
		}
		if strings.EqualFold(candidate.Scheme, parsed.Scheme) &&
			strings.EqualFold(candidate.Host, parsed.Host) &&
			redirectPathAllowed(candidate.Path, parsed.Path) {
			return target
		}
	}
	return fallback
}

func redirectPathAllowed(allowed, path string) bool {
	if allowed == "" || allowed == "/" {
		return true
	}
	allowed = strings.TrimRight(allowed, "/")
	return path == allowed || strings.HasPrefix(path, allowed+"/")
}

func requestScheme(r *http.Request) string {
	if r.TLS != nil {
		return "https"
	}
	if forwarded := firstHeaderValue(r.Header.Get("X-Forwarded-Proto")); forwarded != "" {
		return forwarded
	}
	return "http"
}

func (a *AuthManager) principalFromClaims(claims map[string]any, provider, method string) Principal {
	principal := Principal{
		Subject:  claimString(claims, a.cfg.SubjectClaim),
		Email:    claimString(claims, a.cfg.EmailClaim),
		Name:     claimString(claims, a.cfg.NameClaim),
		Picture:  claimString(claims, a.cfg.PictureClaim),
		Provider: provider,
		Method:   method,
	}
	if principal.Subject == "" {
		principal.Subject = principal.Email
	}
	if principal.Name == "" {
		principal.Name = principal.Email
	}
	return principal
}

func (a *AuthManager) checkAllowed(principal Principal) error {
	if len(a.cfg.AllowedEmails) == 0 && len(a.cfg.AllowedDomains) == 0 {
		return nil
	}
	email := strings.ToLower(strings.TrimSpace(principal.Email))
	if email == "" {
		return errNotAllowed
	}
	for _, allowed := range a.cfg.AllowedEmails {
		if email == strings.ToLower(strings.TrimSpace(allowed)) {
			return nil
		}
	}
	_, domain, ok := strings.Cut(email, "@")
	if ok {
		for _, allowed := range a.cfg.AllowedDomains {
			allowed = strings.ToLower(strings.Trim(strings.TrimSpace(allowed), "."))
			if allowed == "" {
				continue
			}
			if domain == allowed || strings.HasSuffix(domain, "."+allowed) {
				return nil
			}
		}
	}
	return errNotAllowed
}

func (a *AuthManager) matchAPIKey(token string) (apiKey, bool) {
	for _, key := range a.apiKeys {
		if subtle.ConstantTimeCompare([]byte(key.value), []byte(token)) == 1 {
			return key, true
		}
	}
	return apiKey{}, false
}

// HandleLogin starts the authorization code flow with PKCE.
func (a *AuthManager) HandleLogin(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet && r.Method != http.MethodHead {
		methodNotAllowed(w, "GET")
		return
	}
	noStore(w)
	if a.cfg.Mode == authModeNone {
		writeJSON(w, http.StatusNotFound, map[string]any{"error": "interactive login is not configured"})
		return
	}
	md, err := a.provider(r.Context())
	if err != nil {
		a.providerUnavailable(w, err)
		return
	}

	stateToken, err := newRandomToken(32)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]any{"error": "failed to start login"})
		return
	}
	verifier, err := newRandomToken(48)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]any{"error": "failed to start login"})
		return
	}
	nonce, err := newRandomToken(32)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]any{"error": "failed to start login"})
		return
	}

	state := authState{
		State:       stateToken,
		Verifier:    verifier,
		Nonce:       nonce,
		Redirect:    a.safeRedirect(r, r.URL.Query().Get("redirect")),
		RedirectURI: a.redirectURL(r),
		ExpiresAt:   time.Now().Add(stateTTL).Unix(),
	}
	if r.URL.Query().Get("format") == "json" || strings.Contains(r.Header.Get("Accept"), "application/json") {
		state.Mode = "json"
	}
	encodedState, err := encodeAuthState(state, a.cfg.SessionSecret)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]any{"error": "failed to start login"})
		return
	}
	http.SetCookie(w, a.stateCookie(encodedState, int(stateTTL.Seconds())))

	query := url.Values{}
	query.Set("response_type", "code")
	query.Set("client_id", a.cfg.ClientID)
	query.Set("redirect_uri", state.RedirectURI)
	query.Set("state", stateToken)
	query.Set("code_challenge", pkceChallenge(verifier))
	query.Set("code_challenge_method", "S256")
	if len(a.scopes) > 0 {
		query.Set("scope", strings.Join(a.scopes, " "))
	}
	if a.cfg.Mode == authModeOIDC {
		query.Set("nonce", nonce)
	}

	separator := "?"
	if strings.Contains(md.AuthorizationEndpoint, "?") {
		separator = "&"
	}
	destination := md.AuthorizationEndpoint + separator + query.Encode()

	if state.Mode == "json" {
		writeJSON(w, http.StatusOK, map[string]any{
			"authorizationUrl": destination,
			"state":            stateToken,
		})
		return
	}
	http.Redirect(w, r, destination, http.StatusFound)
}

// HandleCallback completes the authorization code flow and issues the session
// cookie.
func (a *AuthManager) HandleCallback(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet && r.Method != http.MethodHead {
		methodNotAllowed(w, "GET")
		return
	}
	noStore(w)
	if a.cfg.Mode == authModeNone {
		writeJSON(w, http.StatusNotFound, map[string]any{"error": "interactive login is not configured"})
		return
	}

	query := r.URL.Query()
	if providerError := query.Get("error"); providerError != "" {
		a.clearCookie(w, a.stateCookie("", 0))
		log.Printf("archview auth: provider returned %q", providerError)
		writeJSON(w, http.StatusUnauthorized, map[string]any{
			"error":             "authorization_failed",
			"providerError":     providerError,
			"providerErrorText": query.Get("error_description"),
		})
		return
	}
	code := query.Get("code")
	stateParam := query.Get("state")
	if code == "" || stateParam == "" {
		writeJSON(w, http.StatusBadRequest, map[string]any{"error": "missing code or state parameter"})
		return
	}

	cookie, err := r.Cookie(stateCookieName)
	if err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]any{"error": "login state is missing or expired"})
		return
	}
	a.clearCookie(w, a.stateCookie("", 0))
	state, err := decodeAuthState(cookie.Value, a.cfg.SessionSecret, time.Now())
	if err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]any{"error": "login state is invalid or expired"})
		return
	}
	if subtle.ConstantTimeCompare([]byte(state.State), []byte(stateParam)) != 1 {
		writeJSON(w, http.StatusBadRequest, map[string]any{"error": "login state mismatch"})
		return
	}

	md, err := a.provider(r.Context())
	if err != nil {
		a.providerUnavailable(w, err)
		return
	}
	token, err := a.exchange(r.Context(), md, code, state.Verifier, state.RedirectURI)
	if err != nil {
		log.Printf("archview auth: token exchange failed: %v", err)
		writeJSON(w, http.StatusBadGateway, map[string]any{"error": "token exchange failed"})
		return
	}
	principal, err := a.principalFromToken(r.Context(), md, token, state.Nonce)
	if err != nil {
		log.Printf("archview auth: token validation failed: %v", err)
		writeJSON(w, http.StatusUnauthorized, map[string]any{"error": "invalid identity token"})
		return
	}
	if err := a.checkAllowed(principal); err != nil {
		log.Printf("archview auth: rejected login for %q", principal.Email)
		writeJSON(w, http.StatusForbidden, map[string]any{"error": "account is not allowed to access this service"})
		return
	}

	now := time.Now()
	expires := now.Add(a.cfg.SessionTTL)
	encodedSession, err := encodeSession(session{
		Subject:   principal.Subject,
		Email:     principal.Email,
		Name:      principal.Name,
		Picture:   principal.Picture,
		Provider:  principal.Provider,
		IssuedAt:  now.Unix(),
		ExpiresAt: expires.Unix(),
	}, a.cfg.SessionSecret)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]any{"error": "failed to create session"})
		return
	}
	http.SetCookie(w, a.sessionCookie(encodedSession, expires))

	if state.Mode == "json" {
		writeJSON(w, http.StatusOK, map[string]any{
			"authenticated": true,
			"user":          principal,
			"expiresAt":     expires.UTC().Format(time.RFC3339),
		})
		return
	}
	http.Redirect(w, r, state.Redirect, http.StatusFound)
}

// HandleLogout clears the session cookie. It is safe to call unauthenticated.
func (a *AuthManager) HandleLogout(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet && r.Method != http.MethodPost {
		methodNotAllowed(w, "GET, POST")
		return
	}
	noStore(w)
	a.clearCookie(w, a.sessionCookie("", time.Now()))

	if r.URL.Query().Get("federated") == "1" {
		if md, err := a.provider(r.Context()); err == nil && md.EndSessionEndpoint != "" {
			if target, err := url.Parse(md.EndSessionEndpoint); err == nil {
				query := target.Query()
				query.Set("client_id", a.cfg.ClientID)
				if a.cfg.PostLogoutRedirect != "" {
					query.Set("post_logout_redirect_uri", a.cfg.PostLogoutRedirect)
				}
				target.RawQuery = query.Encode()
				http.Redirect(w, r, target.String(), http.StatusFound)
				return
			}
		}
	}
	if raw := r.URL.Query().Get("redirect"); raw != "" {
		http.Redirect(w, r, a.safeRedirect(r, raw), http.StatusFound)
		return
	}
	if a.cfg.PostLogoutRedirect != "" {
		http.Redirect(w, r, a.cfg.PostLogoutRedirect, http.StatusFound)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"authenticated": false})
}

// HandleUser returns the authenticated principal.
func (a *AuthManager) HandleUser(w http.ResponseWriter, r *http.Request) {
	noStore(w)
	if principal, ok := PrincipalFromContext(r.Context()); ok {
		writeJSON(w, http.StatusOK, map[string]any{"authenticated": true, "user": principal})
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"authenticated": false, "authEnabled": a.Enabled()})
}

// HandleConfig lets clients discover the login endpoints.
func (a *AuthManager) HandleConfig(w http.ResponseWriter, r *http.Request) {
	noStore(w)
	info := a.PublicInfo()
	if a.cfg.IssuerURL != "" {
		info["issuer"] = a.cfg.IssuerURL
	}
	writeJSON(w, http.StatusOK, info)
}

func methodNotAllowed(w http.ResponseWriter, allow string) {
	w.Header().Set("Allow", allow)
	writeJSON(w, http.StatusMethodNotAllowed, map[string]any{"error": "method not allowed"})
}

func noStore(w http.ResponseWriter) {
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Pragma", "no-cache")
}

func (a *AuthManager) providerUnavailable(w http.ResponseWriter, err error) {
	log.Printf("archview auth: identity provider unavailable: %v", err)
	writeJSON(w, http.StatusServiceUnavailable, map[string]any{"error": "identity provider unavailable"})
}

type tokenResponse struct {
	AccessToken      string `json:"access_token"`
	TokenType        string `json:"token_type"`
	IDToken          string `json:"id_token"`
	ExpiresIn        int64  `json:"expires_in"`
	Scope            string `json:"scope"`
	Error            string `json:"error"`
	ErrorDescription string `json:"error_description"`
}

func (a *AuthManager) exchange(ctx context.Context, md providerMetadata, code, verifier, redirectURI string) (tokenResponse, error) {
	form := url.Values{}
	form.Set("grant_type", "authorization_code")
	form.Set("code", code)
	form.Set("redirect_uri", redirectURI)
	form.Set("client_id", a.cfg.ClientID)
	form.Set("code_verifier", verifier)
	if a.cfg.TokenAuthMethod == "client_secret_post" {
		form.Set("client_secret", a.cfg.ClientSecret)
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, md.TokenEndpoint, strings.NewReader(form.Encode()))
	if err != nil {
		return tokenResponse{}, err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Accept", "application/json")
	req.Header.Set("User-Agent", requestUserAgent)
	if a.cfg.TokenAuthMethod == "client_secret_basic" {
		// RFC 6749 section 2.3.1 requires form-encoding before base64.
		req.SetBasicAuth(url.QueryEscape(a.cfg.ClientID), url.QueryEscape(a.cfg.ClientSecret))
	}

	resp, err := a.client.Do(req)
	if err != nil {
		return tokenResponse{}, err
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(io.LimitReader(resp.Body, maxTokenResponse))
	if err != nil {
		return tokenResponse{}, err
	}

	var token tokenResponse
	_ = json.Unmarshal(body, &token)
	if resp.StatusCode < 200 || resp.StatusCode > 299 {
		return tokenResponse{}, fmt.Errorf("token endpoint returned status %d", resp.StatusCode)
	}
	if token.Error != "" {
		return tokenResponse{}, fmt.Errorf("token endpoint error %q", token.Error)
	}
	if token.AccessToken == "" && token.IDToken == "" {
		return tokenResponse{}, errors.New("token endpoint returned no tokens")
	}
	return token, nil
}

func (a *AuthManager) principalFromToken(ctx context.Context, md providerMetadata, token tokenResponse, nonce string) (Principal, error) {
	provider := md.Issuer
	if provider == "" {
		provider = "oauth2"
	}

	if token.IDToken != "" {
		a.mu.Lock()
		keys := a.jwks
		a.mu.Unlock()
		if keys == nil {
			return Principal{}, errors.New("jwks is not configured")
		}
		claims, err := verifyJWT(ctx, token.IDToken, keys, jwtVerifyOptions{
			Issuer:    md.Issuer,
			Audiences: []string{a.cfg.ClientID},
			Nonce:     nonce,
		})
		if err != nil {
			return Principal{}, err
		}
		principal := a.principalFromClaims(claims, provider, "oidc")
		if principal.Email == "" && md.UserinfoEndpoint != "" && token.AccessToken != "" {
			a.enrichFromUserinfo(ctx, md.UserinfoEndpoint, token.AccessToken, &principal)
		}
		if principal.Subject == "" {
			return Principal{}, errors.New("identity token has no subject")
		}
		return principal, nil
	}

	if md.UserinfoEndpoint == "" || token.AccessToken == "" {
		return Principal{}, errors.New("provider returned no id_token and no userinfo endpoint is configured")
	}
	claims, err := a.fetchUserinfo(ctx, md.UserinfoEndpoint, token.AccessToken)
	if err != nil {
		return Principal{}, err
	}
	principal := a.principalFromClaims(claims, provider, "oauth2")
	if principal.Email == "" && a.cfg.EmailsURL != "" {
		principal.Email = a.fetchVerifiedEmail(ctx, a.cfg.EmailsURL, token.AccessToken)
	}
	if principal.Subject == "" {
		principal.Subject = principal.Email
	}
	if principal.Subject == "" {
		return Principal{}, errors.New("userinfo response has no subject")
	}
	if principal.Name == "" {
		principal.Name = principal.Email
	}
	return principal, nil
}

func (a *AuthManager) enrichFromUserinfo(ctx context.Context, endpoint, accessToken string, principal *Principal) {
	claims, err := a.fetchUserinfo(ctx, endpoint, accessToken)
	if err != nil {
		return
	}
	extra := a.principalFromClaims(claims, principal.Provider, principal.Method)
	if principal.Email == "" {
		principal.Email = extra.Email
	}
	if principal.Name == "" {
		principal.Name = extra.Name
	}
	if principal.Picture == "" {
		principal.Picture = extra.Picture
	}
}

func (a *AuthManager) fetchUserinfo(ctx context.Context, endpoint, accessToken string) (map[string]any, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Authorization", "Bearer "+accessToken)
	req.Header.Set("Accept", "application/json")
	req.Header.Set("User-Agent", requestUserAgent)
	resp, err := a.client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("userinfo request failed: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("userinfo endpoint returned status %d", resp.StatusCode)
	}
	var claims map[string]any
	if err := json.NewDecoder(io.LimitReader(resp.Body, maxJWKSResponse)).Decode(&claims); err != nil {
		return nil, fmt.Errorf("decode userinfo: %w", err)
	}
	return claims, nil
}

func (a *AuthManager) fetchVerifiedEmail(ctx context.Context, endpoint, accessToken string) string {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
	if err != nil {
		return ""
	}
	req.Header.Set("Authorization", "Bearer "+accessToken)
	req.Header.Set("Accept", "application/json")
	req.Header.Set("User-Agent", requestUserAgent)
	resp, err := a.client.Do(req)
	if err != nil {
		return ""
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return ""
	}
	var entries []struct {
		Email    string `json:"email"`
		Primary  bool   `json:"primary"`
		Verified bool   `json:"verified"`
	}
	if err := json.NewDecoder(io.LimitReader(resp.Body, maxJWKSResponse)).Decode(&entries); err != nil {
		return ""
	}
	for _, entry := range entries {
		if entry.Primary && entry.Verified && entry.Email != "" {
			return entry.Email
		}
	}
	for _, entry := range entries {
		if entry.Verified && entry.Email != "" {
			return entry.Email
		}
	}
	return ""
}

// authenticate resolves the caller's identity from a bearer credential or the
// session cookie.
func (a *AuthManager) authenticate(r *http.Request) (Principal, error) {
	if header := r.Header.Get("Authorization"); header != "" {
		scheme, token, ok := strings.Cut(header, " ")
		if !ok || !strings.EqualFold(strings.TrimSpace(scheme), "bearer") {
			return Principal{}, errors.New("unsupported authorization scheme")
		}
		token = strings.TrimSpace(token)
		if token == "" {
			return Principal{}, errNotAuthenticated
		}
		if key, ok := a.matchAPIKey(token); ok {
			return Principal{
				Subject:  "api-key:" + key.label,
				Name:     key.label,
				Provider: "api-key",
				Method:   "api_key",
			}, nil
		}
		if a.cfg.Mode == authModeNone {
			return Principal{}, errNotAuthenticated
		}
		claims, err := a.verifyBearer(r.Context(), token)
		if err != nil {
			return Principal{}, err
		}
		principal := a.principalFromClaims(claims, "bearer", "bearer")
		if principal.Subject == "" {
			return Principal{}, errInvalidToken
		}
		if err := a.checkAllowed(principal); err != nil {
			return Principal{}, err
		}
		return principal, nil
	}

	cookie, err := r.Cookie(a.cfg.CookieName)
	if err != nil || len(a.cfg.SessionSecret) == 0 {
		return Principal{}, errNotAuthenticated
	}
	sess, err := decodeSession(cookie.Value, a.cfg.SessionSecret, time.Now())
	if err != nil {
		return Principal{}, err
	}
	principal := sess.principal()
	if err := a.checkAllowed(principal); err != nil {
		return Principal{}, err
	}
	return principal, nil
}

func (a *AuthManager) verifyBearer(ctx context.Context, token string) (map[string]any, error) {
	a.mu.Lock()
	keys := a.jwks
	issuer := a.cfg.IssuerURL
	a.mu.Unlock()

	if keys == nil {
		md, err := a.provider(ctx)
		if err != nil {
			return nil, err
		}
		if issuer == "" {
			issuer = md.Issuer
		}
		a.mu.Lock()
		keys = a.jwks
		a.mu.Unlock()
	}
	if keys == nil {
		return nil, errors.New("jwks is not configured")
	}
	return verifyJWT(ctx, token, keys, jwtVerifyOptions{
		Issuer:    issuer,
		Audiences: a.audiences,
	})
}

type principalContextKey struct{}

// PrincipalFromContext returns the authenticated identity, if any.
func PrincipalFromContext(ctx context.Context) (Principal, bool) {
	principal, ok := ctx.Value(principalContextKey{}).(Principal)
	return principal, ok
}

// Middleware enforces authentication on every non-public route. Health checks,
// documentation and the OAuth endpoints stay public so a headless frontend or
// orchestrator can use them without credentials.
func (a *AuthManager) Middleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !a.Enabled() || a.isPublicPath(r.URL.Path) {
			next.ServeHTTP(w, r)
			return
		}
		if strings.HasPrefix(r.URL.Path, "/api/") {
			noStore(w)
		}
		principal, err := a.authenticate(r)
		if err != nil {
			response := map[string]any{
				"error":   "unauthorized",
				"message": "authentication required",
			}
			if a.cfg.Mode != authModeNone {
				response["loginUrl"] = "/auth/login"
				w.Header().Set("WWW-Authenticate", `Bearer realm="archview"`)
			}
			writeJSON(w, http.StatusUnauthorized, response)
			return
		}
		ctx := context.WithValue(r.Context(), principalContextKey{}, principal)
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

func (a *AuthManager) isPublicPath(path string) bool {
	switch path {
	case "/", "/healthz", "/readyz", "/auth/login", "/auth/callback", "/auth/logout", "/auth/config":
		return true
	}
	return path == "/docs" || strings.HasPrefix(path, "/docs/")
}
