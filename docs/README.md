# ArchView API Docs

Swagger UI is available at `/docs`; the OpenAPI document is embedded in the
binary and served from `/docs/openapi.yaml`.

## Public endpoints

- `GET /` — service identity (`service`, `version`, `description`)
- `GET /healthz` — liveness
- `GET /readyz` — readiness (also checks the identity provider)
- `GET /docs` — Swagger UI
- `GET /docs/openapi.yaml` — OpenAPI 3.1 document
- `GET /auth/config` — auth mode and login/logout URLs
- `GET /auth/login` — start OAuth login (`?redirect=/path`, `?format=json`)
- `GET /auth/callback` — OAuth callback
- `GET /auth/logout` — clear the session (`?redirect=`, `?federated=1`)

## Protected endpoints

Send either the session cookie created by the login flow or an OAuth 2.0 access
token (client credentials grant or an OIDC bearer JWT):

- `GET /auth/user`
- `GET /api/architecture` — full host overview; optional `?project=` scopes it
- `GET /api/docker`
- `GET /api/system`
- `POST /api/endpoints/{key}/prune-images` — prune dangling images on a managed
  endpoint; `?all=true` prunes all unused images. Requires an administrator: an
  email in `ENDPOINTS_ADMIN_EMAILS`, or a client-credentials caller that is
  listed in `ENDPOINTS_ADMIN_CLIENTS` **and** whose token carries the
  `ENDPOINTS_ADMIN_SCOPE` permission (default `endpoints:admin`).
  `archview:read` alone is not enough.

Unauthenticated requests receive `401` with `WWW-Authenticate: Bearer`.
Authenticated callers that are not endpoint administrators receive `403` from
the endpoint-management route, and the refusal names the missing allowlist
entry or scope. With `AUTH_MODE=none` the whole API, including this destructive
route, is unauthenticated: enable authentication or keep the port unreachable.

