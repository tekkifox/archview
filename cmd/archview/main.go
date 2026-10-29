package main

import (
	"context"
	"errors"
	"log"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/tekkifox/archview/internal/service"
)

func main() {
	cfg, err := loadConfig()
	if err != nil {
		log.Fatalf("invalid configuration: %v", err)
	}

	server, err := service.NewServer(cfg)
	if err != nil {
		log.Fatalf("invalid configuration: %v", err)
	}

	httpServer := &http.Server{
		Addr:              ":" + cfg.Addr,
		Handler:           server.Routes(),
		ReadHeaderTimeout: 10 * time.Second,
		ReadTimeout:       15 * time.Second,
		WriteTimeout:      30 * time.Second,
		IdleTimeout:       60 * time.Second,
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	serverErr := make(chan error, 1)
	go func() {
		log.Printf("archview listening on %s", httpServer.Addr)
		log.Printf("authentication mode: %s", authModeLabel(cfg.Auth))
		if cfg.DockerHost != "" {
			log.Printf("docker host: %s", cfg.DockerHost)
		} else {
			log.Printf("docker socket: %s", cfg.DockerSock)
		}
		log.Printf("host proc: %s", cfg.HostProc)
		serverErr <- httpServer.ListenAndServe()
	}()

	select {
	case err := <-serverErr:
		if err != nil && !errors.Is(err, http.ErrServerClosed) {
			log.Fatalf("server failed: %v", err)
		}
	case <-ctx.Done():
		log.Printf("shutting down")
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
		defer cancel()
		if err := httpServer.Shutdown(shutdownCtx); err != nil {
			log.Printf("graceful shutdown failed: %v", err)
		}
	}
}

func loadConfig() (service.Config, error) {
	auth := service.AuthConfig{
		Mode:                    os.Getenv("AUTH_MODE"),
		IssuerURL:               os.Getenv("OAUTH_ISSUER"),
		DiscoveryURL:            os.Getenv("OAUTH_DISCOVERY_URL"),
		AuthorizationURL:        os.Getenv("OAUTH_AUTHORIZATION_URL"),
		TokenURL:                os.Getenv("OAUTH_TOKEN_URL"),
		UserinfoURL:             os.Getenv("OAUTH_USERINFO_URL"),
		EmailsURL:               os.Getenv("OAUTH_EMAILS_URL"),
		JWKSURL:                 os.Getenv("OAUTH_JWKS_URL"),
		EndSessionURL:           os.Getenv("OAUTH_END_SESSION_URL"),
		ClientID:                os.Getenv("OAUTH_CLIENT_ID"),
		ClientSecret:            os.Getenv("OAUTH_CLIENT_SECRET"),
		RedirectURL:             os.Getenv("OAUTH_REDIRECT_URL"),
		Scopes:                  envList("OAUTH_SCOPES"),
		TokenAuthMethod:         os.Getenv("OAUTH_TOKEN_AUTH_METHOD"),
		SubjectClaim:            os.Getenv("OAUTH_SUBJECT_CLAIM"),
		EmailClaim:              os.Getenv("OAUTH_EMAIL_CLAIM"),
		NameClaim:               os.Getenv("OAUTH_NAME_CLAIM"),
		PictureClaim:            os.Getenv("OAUTH_PICTURE_CLAIM"),
		AllowedEmails:           envList("OAUTH_ALLOWED_EMAILS"),
		AllowedDomains:          envList("OAUTH_ALLOWED_DOMAINS"),
		Audiences:               envList("OAUTH_AUDIENCES"),
		MachineClients:          envList("OAUTH_M2M_CLIENTS"),
		MachineScopes:           envList("OAUTH_M2M_SCOPES"),
		MachineAudiences:        envList("OAUTH_M2M_AUDIENCES"),
		IntrospectionURL:        os.Getenv("OAUTH_INTROSPECTION_URL"),
		IntrospectionAuthMethod: os.Getenv("OAUTH_INTROSPECTION_AUTH_METHOD"),
		IntrospectionMethod:     os.Getenv("OAUTH_INTROSPECTION_METHOD"),
		SessionSecret:           []byte(os.Getenv("SESSION_SECRET")),
		SessionTTL:              envDuration("SESSION_TTL", 8*time.Hour),
		StateTTL:                envDuration("OAUTH_STATE_TTL", 10*time.Minute),
		CookieName:              os.Getenv("SESSION_COOKIE_NAME"),
		CookieDomain:            os.Getenv("SESSION_COOKIE_DOMAIN"),
		CookieSameSite:          os.Getenv("SESSION_COOKIE_SAMESITE"),
		CookieSecure:            envBool("SESSION_COOKIE_SECURE", true),
		PostLoginRedirect:       envOrDefault("OAUTH_POST_LOGIN_REDIRECT", "/"),
		PostLogoutRedirect:      os.Getenv("OAUTH_POST_LOGOUT_REDIRECT"),
		AllowedRedirectURLs:     envList("OAUTH_ALLOWED_REDIRECT_URLS"),
		AllowInsecureHTTP:       envBool("OAUTH_ALLOW_INSECURE_HTTP", false),
		TrustProxyHeaders:       envBool("TRUST_PROXY_HEADERS", false),
		HTTPTimeout:             envDuration("OAUTH_HTTP_TIMEOUT", 10*time.Second),
	}

	mode := strings.ToLower(strings.TrimSpace(auth.Mode))
	if (mode == "" || mode == "none") &&
		auth.IssuerURL == "" && auth.DiscoveryURL == "" && auth.AuthorizationURL == "" {
		log.Printf("WARNING: authentication is disabled; set AUTH_MODE=oidc to protect this deployment")
	}
	if strings.TrimSpace(os.Getenv("API_KEYS")) != "" {
		log.Printf("WARNING: API_KEYS is no longer supported and is ignored; machine clients must request an OAuth 2.0 access token with the client_credentials grant")
	}

	return service.Config{
		Addr:        envOrDefault("PORT", "8080"),
		DockerAPI:   envOrDefault("DOCKER_API_VERSION", "v1.41"),
		DockerHost:  envOrDefault("DOCKER_HOST", ""),
		DockerSock:  envOrDefault("DOCKER_SOCKET", "/var/run/docker.sock"),
		HostProc:    envOrDefault("HOST_PROC", "/host/proc"),
		HostSys:     envOrDefault("HOST_SYS", "/host/sys"),
		HostRoot:    envOrDefault("HOST_ROOT", "/host/root"),
		CORSOrigins: envList("CORS_ALLOWED_ORIGINS"),
		Auth:        auth,
	}, nil
}

func authModeLabel(cfg service.AuthConfig) string {
	mode := strings.ToLower(strings.TrimSpace(cfg.Mode))
	if mode == "" {
		switch {
		case cfg.IssuerURL != "" || cfg.DiscoveryURL != "":
			mode = "oidc"
		case cfg.AuthorizationURL != "":
			mode = "oauth2"
		default:
			mode = "none"
		}
	}
	if mode == "none" {
		return "none (unauthenticated)"
	}
	return mode
}

func envOrDefault(key, fallback string) string {
	if value := strings.TrimSpace(os.Getenv(key)); value != "" {
		return value
	}
	return fallback
}

func envList(key string) []string {
	raw := os.Getenv(key)
	if strings.TrimSpace(raw) == "" {
		return nil
	}
	values := strings.FieldsFunc(raw, func(r rune) bool {
		return r == ',' || r == '\n' || r == '\r' || r == '\t' || r == ' '
	})
	result := make([]string, 0, len(values))
	for _, value := range values {
		if value = strings.TrimSpace(value); value != "" {
			result = append(result, value)
		}
	}
	return result
}

func envBool(key string, fallback bool) bool {
	value := strings.ToLower(strings.TrimSpace(os.Getenv(key)))
	switch value {
	case "":
		return fallback
	case "1", "true", "yes", "on":
		return true
	case "0", "false", "no", "off":
		return false
	default:
		return fallback
	}
}

func envDuration(key string, fallback time.Duration) time.Duration {
	value := strings.TrimSpace(os.Getenv(key))
	if value == "" {
		return fallback
	}
	parsed, err := time.ParseDuration(value)
	if err != nil {
		log.Printf("WARNING: %s=%q is not a valid duration, using %s", key, value, fallback)
		return fallback
	}
	return parsed
}
