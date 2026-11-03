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
  endpoint; `?all=true` prunes all unused images. Requires an administrator
  (`ENDPOINTS_ADMIN_EMAILS` or `ENDPOINTS_ADMIN_CLIENTS`).

Unauthenticated requests receive `401` with `WWW-Authenticate: Bearer`.
Authenticated callers that are not endpoint administrators receive `403` from
the endpoint-management route.

