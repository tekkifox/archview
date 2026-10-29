# ArchView

ArchView is a headless Go microservice that collects Docker daemon data, container and image inventory, and Linux host metrics, then exposes them over a JSON API protected by OAuth/OIDC.

It ships **no frontend and no dashboard**. Any number of separate sites, dashboards, or services can consume the API; each deployment is secured independently.

## Features

- JSON-only API (no bundled UI)
- OAuth 2.0 / OpenID Connect login with PKCE, state and nonce validation
- Non-OIDC OAuth 2.0 providers (for example GitHub) through userinfo
- Stateless, signed session cookies: no database, safe to run multiple replicas
- Machine-to-machine access with the OAuth 2.0 client credentials grant (no shared API keys)
- Bearer JWT validation against the provider's JWKS plus RFC 7662 introspection for opaque tokens
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

`FULL_DOCKER_PROJECTS` widens the `/api/architecture` response for selected projects. It is a comma-separated list of project labels — not newline-separated. Labels are matched after alias normalisation, so `image-mosaic` and `photoprism` both arrive as the canonical `travelling`; matching is case-sensitive and surrounding spaces around each entry are trimmed. Because matching happens on the normalised label, `FULL_DOCKER_PROJECTS` must list `travelling`, not the alias. When a project matches, the endpoint returns the **full host and Docker overview** (every container and image) instead of the project-scoped snapshot. When unset, every project stays scoped.

Every overview and architecture response also carries an `endpoints` array with
absolute URLs for the instance that served the request, so a consumer can
discover the rest of the API:

```json
"endpoints": [
  {"name": "overview", "url": "https://archview.example.com/api/overview"},
  {"name": "architecture", "url": "https://archview.example.com/api/architecture?project=<name>"},
  {"name": "docker", "url": "https://archview.example.com/api/docker"},
  {"name": "system", "url": "https://archview.example.com/api/system"},
  {"name": "healthz", "url": "https://archview.example.com/healthz"},
  {"name": "readyz", "url": "https://archview.example.com/readyz"},
  {"name": "docs", "url": "https://archview.example.com/docs"}
]
```

The URLs follow the request's scheme and host. `X-Forwarded-Proto` and
`X-Forwarded-Host` are honoured only when `TRUST_PROXY_HEADERS=true`, which is
the same rule used for login redirects and cookies. The `diagram` string shows
the instance's `/api` base URL inline against the API hop (when the topology has
one); the full endpoint list stays in the `endpoints` array.

## Response shape

Responses are deliberately limited to what the console needs. The API does not
return host internals or anything that could carry a secret:

- containers expose a 12-character ID, name, image, state, status and creation
  time only — no ports, commands, labels or mount counts;
- images expose repo tags, size, creation time and dangling state — no image
  ID, architecture or OS;
- the Docker daemon exposes its operating system, architecture, driver, CPU
  count, memory total and container/image counts — no kernel, root directory,
  server version or API version;
- `system` exposes CPU count, load average, memory, process count, disk byte
  totals and percentages, and network byte counters — no kernel, uptime,
  architecture, mount points, filesystems or interface names;
- `NodeSummary.details` only carries a container's `image` and `state`.

`hostname` and `os` are kept deliberately so a dashboard can identify which host
it is viewing. Telemetry derives the same safe values.

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
| `Authorization: Bearer <access-token>` | Machines using the OAuth client credentials grant, or callers that already hold an OIDC access/ID token |

There are no static API keys: every machine gets its own token from the identity
provider, so a leaked credential can be revoked and rotated there without
touching ArchView.

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

### 5. Machine-to-machine access (OAuth client credentials)

Services authenticate **to the identity provider**, not to ArchView, and send the
resulting access token as a bearer token:

```bash
# 1. Ask the identity provider for a token with the client credentials grant.
TOKEN=$(curl -s -X POST "$OAUTH_TOKEN_URL" \
  -u "$CLIENT_ID:$CLIENT_SECRET" \
  -d "grant_type=client_credentials" \
  -d "scope=archview:read" | jq -r .access_token)

# 2. Call ArchView with it.
curl -H "Authorization: Bearer $TOKEN" https://archview.example.com/api/system
```

ArchView validates the token and never stores a shared secret:

- **JWT access tokens** are verified against the provider JWKS (`exp`, `nbf`,
  `iss`, `aud`) exactly like human tokens. Use `OAUTH_M2M_AUDIENCES` when the
  provider issues a different `aud` for applications than `OAUTH_CLIENT_ID`.
- **Opaque access tokens** are validated through RFC 7662 introspection, enabled
  with `OAUTH_INTROSPECTION_URL`. Google service accounts issue opaque tokens;
  point it at `https://oauth2.googleapis.com/tokeninfo` with
  `OAUTH_INTROSPECTION_METHOD=GET` and `OAUTH_INTROSPECTION_AUTH_METHOD=none`.

Optional restrictions:

```bash
# Only these OAuth clients (Client IDs, not names) may call the API as machines.
OAUTH_M2M_CLIENTS=monitoring,ci
# Tokens must carry all of these scopes.
OAUTH_M2M_SCOPES=archview:read
```

Machine tokens bypass `OAUTH_ALLOWED_EMAILS`/`OAUTH_ALLOWED_DOMAINS` (they have no
email) and are governed by the two allowlists above. `/auth/user` reports them
with `"method": "client_credentials"` and `"sub": "client:<client_id>"`.

### 6. Bearer JWTs

In `oidc` mode, JWTs signed by the provider are accepted. ArchView verifies the signature against the provider JWKS and checks `exp`, `nbf`, `iss` and `aud`. Accepted audiences default to `OAUTH_CLIENT_ID` and can be extended with `OAUTH_AUDIENCES`.


## Troubleshooting login

`login state is missing or expired` means the callback arrived without the
`archview_oauth_state` cookie. The callback now logs the host, scheme, cookie
attributes and received cookie names, and the JSON response carries a `hint`.
The usual causes:

| Symptom | Fix |
| --- | --- |
| `SESSION_COOKIE_SECURE=true` but `/auth/login` is reached over http | Serve the login over https, or set `TRUST_PROXY_HEADERS=true` so `X-Forwarded-Proto: https` is honoured |
| Login starts on one host and the callback lands on another (`www.` vs apex, http vs https) | Use the same hostname as `OAUTH_REDIRECT_URL` for both steps |
| `SESSION_COOKIE_SAMESITE=strict` | The state cookie is forced to `lax`; the setting only affects the session cookie now |
| The provider consent screen (MFA, account chooser) takes longer than the state lifetime | Raise `OAUTH_STATE_TTL` (default `10m`, maximum `1h`) |
| Multiple replicas with different `SESSION_SECRET` values | Share one secret; otherwise the error is `login state is invalid or expired` |
| Reverse proxy mounts ArchView under a path prefix | The state cookie is scoped to `/`, so it is sent to `/prefix/auth/callback` |

For Google specifically:

- `OAUTH_ISSUER=https://accounts.google.com` is correct; ID tokens that carry
  `iss: accounts.google.com` (without the scheme) are accepted too.
- `OAUTH_REDIRECT_URL` must match the authorised redirect URI byte for byte
  (`https://…/auth/callback`, no trailing slash).
- Google does not implement the client credentials grant. For machine access use
  a service account and validate its opaque token through
  `OAUTH_INTROSPECTION_URL=https://oauth2.googleapis.com/tokeninfo` with
  `OAUTH_INTROSPECTION_METHOD=GET` and `OAUTH_INTROSPECTION_AUTH_METHOD=none`.

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
| `FULL_DOCKER_PROJECTS` | — | Comma-separated normalised project labels that receive the full host and Docker overview; matched case-sensitively after trimming; empty keeps every project scoped |

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
| `OAUTH_AUDIENCES` | `OAUTH_CLIENT_ID` | Accepted `aud` values for human bearer JWTs |
| `OAUTH_M2M_AUDIENCES` | `OAUTH_AUDIENCES` | Accepted `aud` values for machine (client credentials) tokens |
| `OAUTH_M2M_CLIENTS` | — | Comma-separated client IDs allowed to call the API as machines |
| `OAUTH_M2M_SCOPES` | — | Comma-separated scopes a machine token must carry |
| `OAUTH_INTROSPECTION_URL` | — | RFC 7662 introspection endpoint for opaque access tokens |
| `OAUTH_INTROSPECTION_METHOD` | `POST` | `POST` (RFC 7662) or `GET` (Google tokeninfo) |
| `OAUTH_INTROSPECTION_AUTH_METHOD` | `client_secret_basic` | `client_secret_basic`, `client_secret_post` or `none` |
| `OAUTH_STATE_TTL` | `10m` | Lifetime of the OAuth state cookie (maximum `1h`) |
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

## This deployment: archview.rossmoney.me

`docker-compose.portainer.yml` is the stack used for `archview.rossmoney.me`. It
joins the external `proxy` network at a fixed address (`172.18.0.10`) and
listens on port `8083`; the host's openresty reverse proxy terminates TLS for
`archview.rossmoney.me` and forwards to that address. ArchView trusts the
proxy's `X-Forwarded-Proto`/`X-Forwarded-Host` headers, which is why the login
redirect sent to the identity provider uses `https://` and the public hostname
instead of the container's own address.

`stack.env` for that stack:

```ini
PORT="8083"

DOCKER_HOST=tcp://socket-proxy:2375
DOCKER_API_VERSION="v1.44"
HOST_PROC=/host/proc
HOST_SYS=/host/sys
HOST_ROOT=/host/root

# --- Login ---------------------------------------------------------------
# Auth0 tenant issuer (Auth0 publishes it with a trailing slash).
AUTH_MODE=oidc
OAUTH_ISSUER=https://<tenant>.auth0.com/
OAUTH_CLIENT_ID=archview
OAUTH_CLIENT_SECRET=replace-me
# Must match the callback registered with Auth0 byte for byte.
OAUTH_REDIRECT_URL=https://archview.rossmoney.me/auth/callback
OAUTH_SCOPES="openid profile email"
# Optional: restrict who may log in.
OAUTH_ALLOWED_EMAILS=you@example.com
# Where the browser lands after logging in ("/" shows the JSON service index).
OAUTH_POST_LOGIN_REDIRECT=/

# 32+ random bytes: openssl rand -base64 48. Identical on every replica.
SESSION_SECRET=replace-with-at-least-32-random-bytes
SESSION_TTL=8h
SESSION_COOKIE_SECURE=true
SESSION_COOKIE_SAMESITE=lax

# Machine-to-machine client used by the rossmoney.me CMS (/api/architecture
# proxy). Access tokens are issued by Auth0 for the API identifier below: their
# aud is https://archview.rossmoney.me/api, their azp is the Client ID of the
# "cms" application and their scope contains archview:read.
# Takes the Auth0 Client ID of the "cms" application (the opaque value from its
# Settings), not the application name.
OAUTH_M2M_CLIENTS=<cms-app-client-id>
OAUTH_M2M_SCOPES=archview:read
OAUTH_M2M_AUDIENCES=https://archview.rossmoney.me/api

TRUST_PROXY_HEADERS=true
```

Steps to bring it up:

1. In Auth0, create a **Regular Web Application** named `archview` and register
   `https://archview.rossmoney.me/auth/callback` as an allowed callback URL.
   `OAUTH_CLIENT_ID` and `OAUTH_CLIENT_SECRET` are its Client ID and Client
   Secret; `OAUTH_REDIRECT_URL` is that same callback URI.
2. Create an **API** whose identifier is `https://archview.rossmoney.me/api` and
   define the `archview:read` permission. Enable *Add Permissions in the Access
   Token* so the permission appears in the token's `scope`.
3. Create a **Machine-to-Machine Application** named `cms` and authorize it for
   that API with `archview:read`. `OAUTH_M2M_CLIENTS` takes its Client ID — the
   opaque value from the application's Settings, not its name — while
   `OAUTH_M2M_SCOPES` holds the required permission and `OAUTH_M2M_AUDIENCES`
   the API identifier.
4. Put the values above in the stack's `stack.env` in Portainer and deploy
   `docker-compose.portainer.yml`.
5. Point the openresty server block for `archview.rossmoney.me` at
   `172.18.0.10:8083` and pass `Host`, `X-Forwarded-Proto` and
   `X-Forwarded-For` through unchanged.
6. Store the CMS client ID and secret in the CMS stack as
   `ARCHVIEW_CLIENT_ID`/`ARCHVIEW_CLIENT_SECRET`, with
   `ARCHVIEW_URL=https://archview.rossmoney.me`. The CMS exchanges them for a
   token at `https://<tenant>.auth0.com/oauth/token` with the
   client-credentials grant, `audience=https://archview.rossmoney.me/api` and
   `scope=archview:read`, then calls ArchView with the access token.

Auth0 issues signed JWT access tokens, so no `OAUTH_INTROSPECTION_*` settings
are needed: ArchView verifies them against the tenant JWKS. For an opaque-token
provider such as Google, configure `OAUTH_INTROSPECTION_URL` instead (Google
service accounts use `https://oauth2.googleapis.com/tokeninfo` with
`OAUTH_INTROSPECTION_METHOD=GET` and `OAUTH_INTROSPECTION_AUTH_METHOD=none`);
that is not this deployment because Auth0 access tokens are signed JWTs.

Verify the boundary:

```bash
# Anonymous API call is rejected and advertises the scheme.
curl -sI https://archview.rossmoney.me/api/architecture | grep -i www-authenticate

# The login entry point hands the browser to the identity provider.
curl -sI https://archview.rossmoney.me/auth/login | grep -i location

# A client-credentials token gets a snapshot without a browser session.
TOKEN=$(curl -s -X POST "https://<tenant>.auth0.com/oauth/token" \
  -H "Content-Type: application/json" \
  -d "{\"grant_type\":\"client_credentials\",\"client_id\":\"$ARCHVIEW_CLIENT_ID\",\"client_secret\":\"$ARCHVIEW_CLIENT_SECRET\",\"audience\":\"https://archview.rossmoney.me/api\",\"scope\":\"archview:read\"}" \
  | jq -r .access_token)
curl -s -H "Authorization: Bearer $TOKEN" \
  "https://archview.rossmoney.me/api/architecture?project=travelling" | head -c 200
```

The public site never calls ArchView from the browser: cross-site requests would
not carry the session cookie, so the CMS reaches the API from its own server
through `/api/architecture` and forwards the response. Open
`https://archview.rossmoney.me/auth/login` directly in a browser to use the
interactive login.

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
  -H "Authorization: Bearer $TOKEN" \
  https://archview.example.com/api/architecture?project=travelling | jq .
```

## Development

```bash
make fmt
make vet
make test
go test -race ./...
```

The test suite covers the PKCE/state/nonce login flow, JWT and JWKS validation, client-credentials and introspection auth, allowlists, CORS, security headers and the absence of the old dashboard.

## Security notes

- Never mount the Docker socket directly into ArchView; use a socket proxy with `POST=0`.
- Keep `AUTH_MODE=none` out of production. The service logs a warning when authentication is disabled.
- Prefer allowlists (`OAUTH_ALLOWED_EMAILS` / `OAUTH_ALLOWED_DOMAINS`) for private APIs.
- Provider endpoints must use HTTPS unless they are loopback addresses; `OAUTH_ALLOW_INSECURE_HTTP` exists for local development.
- Session and OAuth state cookies are signed and verified in constant time; JWT signatures are verified against the provider JWKS with key-rotation support.
- Bearer tokens, client secrets and introspected tokens are never written to responses or logs.

