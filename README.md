# ArchView

ArchView is a headless Go microservice that collects Docker daemon data, container and image inventory, and Linux host metrics, then exposes them over a JSON API protected by OAuth/OIDC.

It ships **no frontend and no dashboard**. Any number of separate sites, dashboards, or services can consume the API; each deployment is secured independently.

## Features

- JSON-only API (no bundled UI)
- OAuth 2.0 / OpenID Connect login with PKCE, state and nonce validation
- Non-OIDC OAuth 2.0 providers (for example GitHub) through userinfo
- Stateless, signed session cookies: no database, safe to run multiple replicas
- Bearer JWT validation against the provider's JWKS and static API keys for service-to-service calls
- Email/domain allowlists
- Configurable CORS, security headers, health and readiness probes
- Embedded OpenAPI specification with Swagger UI at `/docs`
- Standard library only — no third-party Go dependencies

## Endpoints

| Path | Auth | Description |
| --- | --- | --- |
| `GET /` | public | Service index and auth metadata (JSON) |
| `GET /healthz` | public | Liveness probe |
| `GET /readyz` | public | Readiness probe (also checks the identity provider) |
| `GET /docs` | public | Swagger UI |
| `GET /docs/openapi.yaml` | public | OpenAPI 3.1 specification |
| `GET /auth/config` | public | Auth mode and login/logout URLs |
| `GET /auth/login` | public | Starts the authorization code flow |
| `GET /auth/callback` | public | OAuth callback; sets the session cookie |
| `GET /auth/logout` | public | Clears the session cookie |
| `GET /auth/user` | protected | Current principal |
| `GET /api/overview` | protected | Full Docker + host overview |
| `GET /api/architecture?project=<name>` | protected | Project-scoped overview with telemetry |
| `GET /api/docker` | protected | Docker daemon, container and image inventory |
| `GET /api/system` | protected | Linux host metrics |

Protected endpoints return `401` with a `WWW-Authenticate: Bearer` header when no valid credential is present.

## Quick start

```bash
go build ./cmd/archview

PORT=8080 \
DOCKER_HOST=tcp://socket-proxy:2375 \
HOST_PROC=/host/proc \
HOST_SYS=/host/sys \
HOST_ROOT=/host/root \
AUTH_MODE=none \
go run ./cmd/archview
```

`AUTH_MODE=none` is intended for local experiments only; the process logs a warning. See [Authentication](#authentication) for production configuration.

## Authentication

Every protected request must present **one** of:

| Credential | Use case |
| --- | --- |
| Signed session cookie | Browsers after the OAuth login flow |
| `Authorization: Bearer <api-key>` | Service-to-service, monitoring, CI |
| `Authorization: Bearer <jwt>` | Callers that already hold an OIDC access/ID token |

### 1. Register an OAuth application

Create an application with your identity provider (Google, Microsoft Entra ID, Okta, Auth0, Keycloak, ...) and register the callback URL:

```text
https://archview.example.com/auth/callback
```

Request the `openid profile email` scopes.

### 2. Configure ArchView (OIDC)

```bash
AUTH_MODE=oidc
OAUTH_ISSUER=https://accounts.example.com
OAUTH_CLIENT_ID=archview
OAUTH_CLIENT_SECRET=replace-me
OAUTH_REDIRECT_URL=https://archview.example.com/auth/callback
OAUTH_SCOPES="openid profile email"

# 32+ random bytes, identical on every replica: openssl rand -base64 48
SESSION_SECRET=replace-with-a-long-random-value
SESSION_TTL=8h

# Optional allowlist. With both empty, any identity accepted by the provider
# can use the API.
OAUTH_ALLOWED_EMAILS=ross@example.com
OAUTH_ALLOWED_DOMAINS=example.com
```

The service fetches `/.well-known/openid-configuration` (or `OAUTH_DISCOVERY_URL`), validates the issuer, and caches the provider metadata and signing keys.

### 3. Non-OIDC OAuth 2.0 providers (GitHub example)

```bash
AUTH_MODE=oauth2
OAUTH_AUTHORIZATION_URL=https://github.com/login/oauth/authorize
OAUTH_TOKEN_URL=https://github.com/login/oauth/access_token
OAUTH_USERINFO_URL=https://api.github.com/user
OAUTH_EMAILS_URL=https://api.github.com/user/emails
OAUTH_SCOPES="read:user user:email"
OAUTH_SUBJECT_CLAIM=id
OAUTH_NAME_CLAIM=login
OAUTH_CLIENT_ID=...
OAUTH_CLIENT_SECRET=...
OAUTH_REDIRECT_URL=https://archview.example.com/auth/callback
SESSION_SECRET=...
```

In this mode ArchView exchanges the code (PKCE is always used), reads the userinfo endpoint, and resolves a verified email address if the provider hides it on the profile.


### 4. Browser / SPA integration

The API is cookie based, so a frontend on the **same site** can simply use credentials:

```js
const res = await fetch("https://archview.example.com/api/system", {
  credentials: "include"
});

if (res.status === 401) {
  // Send the user through the login flow; it returns to /auth/login?redirect=...
  window.location.href =
    "https://archview.example.com/auth/login?redirect=" +
    encodeURIComponent(window.location.href);
}
```

`GET /auth/login` redirects the browser to the provider. After the callback, the session cookie is set and the browser is sent back to `redirect` (relative paths or allowlisted absolute URLs only).

The callback URL is fixed by `OAUTH_REDIRECT_URL`; configure additional post-login targets with `OAUTH_ALLOWED_REDIRECT_URLS`.

For a frontend on a **different site**, either:

- call the API through a small backend-for-frontend that holds the session, or
- set `SESSION_COOKIE_SAMESITE=none` **and** `SESSION_COOKIE_SECURE=true` and list the frontend origin in `CORS_ALLOWED_ORIGINS`.

Session cookies are `HttpOnly`, `Secure` (by default), and signed with HMAC-SHA256. The session payload contains only the subject, email, name, picture, provider and expiry — no provider tokens — so replicas only need the shared `SESSION_SECRET`.

### 5. Machine-to-machine API keys

```bash
API_KEYS="monitoring:2f7c...d41,ci:91ab...7e0"
```

```bash
curl -H "Authorization: Bearer 2f7c...d41" https://archview.example.com/api/system
```

Only the label (`monitoring`) is reported in `/auth/user` and logs; the key itself is never echoed. API keys do not require an identity provider or `SESSION_SECRET`.

### 6. Bearer JWTs

In `oidc` mode, JWTs signed by the provider are accepted. ArchView verifies the signature against the provider JWKS and checks `exp`, `nbf`, `iss` and `aud`. Accepted audiences default to `OAUTH_CLIENT_ID` and can be extended with `OAUTH_AUDIENCES`.


## Configuration reference

### Runtime

| Variable | Default | Description |
| --- | --- | --- |
| `PORT` | `8080` | HTTP listen port |
| `DOCKER_HOST` | — | Docker endpoint, e.g. `tcp://socket-proxy:2375` |
| `DOCKER_SOCKET` | `/var/run/docker.sock` | Unix socket used when `DOCKER_HOST` is empty |
| `DOCKER_API_VERSION` | `v1.41` | Docker API version prefix |
| `HOST_PROC` | `/host/proc` | Mounted host `/proc` |
| `HOST_SYS` | `/host/sys` | Mounted host `/sys` |
| `HOST_ROOT` | `/host/root` | Mounted host root (for disk stats) |
| `CORS_ALLOWED_ORIGINS` | — | Comma-separated exact origins; empty means same-origin only |
| `TRUST_PROXY_HEADERS` | `false` | Honour `X-Forwarded-Proto`/`X-Forwarded-Host` |

### Authentication

| Variable | Default | Description |
| --- | --- | --- |
| `AUTH_MODE` | inferred | `none`, `oidc` or `oauth2`; empty infers from the values below |
| `OAUTH_ISSUER` | — | OIDC issuer (enables discovery) |
| `OAUTH_DISCOVERY_URL` | issuer + `/.well-known/openid-configuration` | Explicit discovery document |
| `OAUTH_AUTHORIZATION_URL` | from discovery | Explicit authorization endpoint |
| `OAUTH_TOKEN_URL` | from discovery | Explicit token endpoint |
| `OAUTH_USERINFO_URL` | from discovery | Explicit userinfo endpoint |
| `OAUTH_EMAILS_URL` | — | Optional verified-email endpoint (GitHub style) |
| `OAUTH_JWKS_URL` | from discovery | Explicit JWKS URL |
| `OAUTH_END_SESSION_URL` | from discovery | Provider logout endpoint for `?federated=1` |
| `OAUTH_CLIENT_ID` | — | Required when auth is enabled |
| `OAUTH_CLIENT_SECRET` | — | Client secret (public clients may omit it) |
| `OAUTH_REDIRECT_URL` | derived from the request | Must match the provider registration |
| `OAUTH_SCOPES` | `openid profile email` for OIDC | Space or comma separated |
| `OAUTH_TOKEN_AUTH_METHOD` | `client_secret_basic` | `client_secret_basic`, `client_secret_post` or `none` |
| `OAUTH_SUBJECT_CLAIM` | `sub` | Claim used as the principal subject |
| `OAUTH_EMAIL_CLAIM` | `email` | Email claim |
| `OAUTH_NAME_CLAIM` | `name` | Display name claim |
| `OAUTH_PICTURE_CLAIM` | `picture` | Avatar claim |
| `OAUTH_ALLOWED_EMAILS` | — | Comma-separated exact email allowlist |
| `OAUTH_ALLOWED_DOMAINS` | — | Comma-separated domains (subdomains included) |
| `OAUTH_AUDIENCES` | `OAUTH_CLIENT_ID` | Accepted `aud` values for bearer JWTs |
| `API_KEYS` | — | Comma-separated `key` or `label:key` static bearer tokens |
| `SESSION_SECRET` | — | 32+ bytes; signs session and OAuth state cookies |
| `SESSION_TTL` | `8h` | Session lifetime (maximum `720h`) |
| `SESSION_COOKIE_NAME` | `archview_session` | Session cookie name |
| `SESSION_COOKIE_DOMAIN` | — | Optional cookie domain |
| `SESSION_COOKIE_SECURE` | `true` | Set `false` only for plain-HTTP development |
| `SESSION_COOKIE_SAMESITE` | `lax` | `lax`, `strict` or `none` |
| `OAUTH_POST_LOGIN_REDIRECT` | `/` | Default post-login destination |
| `OAUTH_POST_LOGOUT_REDIRECT` | — | Default post-logout destination |
| `OAUTH_ALLOWED_REDIRECT_URLS` | — | Absolute URLs allowed for `?redirect=` (scheme + host + optional path prefix) |
| `OAUTH_ALLOW_INSECURE_HTTP` | `false` | Allow `http://` provider endpoints (local development only) |
| `OAUTH_HTTP_TIMEOUT` | `10s` | Timeout for provider requests |

`SESSION_SECRET` must be identical on every replica. Rotating it invalidates all sessions (users simply log in again).


## Deploy with Docker Compose

```yaml
services:
  socket-proxy:
    image: lscr.io/linuxserver/socket-proxy:latest
    environment:
      CONTAINERS: "1"
      IMAGES: "1"
      INFO: "1"
      PING: "1"
      POST: "0"
      VERSION: "1"
    volumes:
      - /var/run/docker.sock:/var/run/docker.sock:ro
    read_only: true
    tmpfs:
      - /run

  archview:
    image: ghcr.io/YOUR_ORG_OR_USER/archview:latest
    env_file:
      - stack.env
    ports:
      - "8080:8080"
    volumes:
      - /proc:/host/proc:ro
      - /sys:/host/sys:ro
      - /:/host/root:ro
    depends_on:
      - socket-proxy
    restart: unless-stopped
    healthcheck:
      test: ["CMD-SHELL", "wget -qO- http://127.0.0.1:8080/healthz >/dev/null || exit 1"]
      interval: 30s
      timeout: 5s
      retries: 3
```

The socket proxy is the only container that mounts `/var/run/docker.sock`. ArchView only needs read-only host mounts.

## Microservice notes

- **Stateless**: no database, no local session store, no bundled UI. Scale horizontally behind a load balancer with the same `SESSION_SECRET`.
- **Independent deployments**: each instance has its own OAuth client and allowlist, so one API can serve several sites with different access rules.
- **CORS is explicit**: no wildcard by default. Add each consuming origin to `CORS_ALLOWED_ORIGINS`.
- **Probes**: `/healthz` for liveness, `/readyz` for readiness (returns `503` when the identity provider cannot be reached).
- **TLS**: terminate TLS at your reverse proxy/ingress and keep `SESSION_COOKIE_SECURE=true`.
- **Docs travel with the binary**: the OpenAPI spec is embedded, so no files or volumes are needed at runtime.

Example request:

```bash
curl -s \
  -H "Authorization: Bearer $ARCHVIEW_API_KEY" \
  https://archview.example.com/api/architecture?project=image-mosaic | jq .
```

## Development

```bash
make fmt
make vet
make test
go test -race ./...
```

The test suite covers the PKCE/state/nonce login flow, JWT and JWKS validation, API key auth, allowlists, CORS, security headers and the absence of the old dashboard.

## Security notes

- Never mount the Docker socket directly into ArchView; use a socket proxy with `POST=0`.
- Keep `AUTH_MODE=none` out of production. The service logs a warning when authentication is disabled.
- Prefer allowlists (`OAUTH_ALLOWED_EMAILS` / `OAUTH_ALLOWED_DOMAINS`) for private APIs.
- Provider endpoints must use HTTPS unless they are loopback addresses; `OAUTH_ALLOW_INSECURE_HTTP` exists for local development.
- Session and OAuth state cookies are signed and verified in constant time; JWT signatures are verified against the provider JWKS with key-rotation support.
- API keys and client secrets are never written to responses or logs.

