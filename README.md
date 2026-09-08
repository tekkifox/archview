# ArchView

ArchView is a separate Go service that collects Docker daemon data, container and image inventory, and Linux host metrics, then exposes them over JSON APIs and a small built-in dashboard.

## Repository layout

```text
go-service/
  cmd/archview/main.go
  internal/service/server.go
  go.mod
  Dockerfile
  README.md
  .github/workflows/docker-publish.yml
```

## What it exposes

- `GET /healthz`
- `GET /api/overview`
- `GET /api/architecture`
- `GET /api/docker`
- `GET /api/system`

## Build locally

```bash
go build ./cmd/archview
```

Run it with environment variables if needed:

```bash
PORT=8080 \
DOCKER_SOCKET=/var/run/docker.sock \
HOST_PROC=/host/proc \
HOST_SYS=/host/sys \
HOST_ROOT=/host/root \
go run ./cmd/archview
```

## Build the container image

```bash
docker build -t archview:latest .
```

## Deploy as a separate service

Run the container on a Linux host with the Docker socket and host mounts exposed read-only:

```yaml
services:
  archview:
    image: ghcr.io/YOUR_ORG_OR_USER/archview:latest
    ports:
      - "8080:8080"
    environment:
      PORT: "8080"
      DOCKER_SOCKET: "/var/run/docker.sock"
      HOST_PROC: "/host/proc"
      HOST_SYS: "/host/sys"
      HOST_ROOT: "/host/root"
    volumes:
      - /var/run/docker.sock:/var/run/docker.sock
      - /proc:/host/proc:ro
      - /sys:/host/sys:ro
      - /:/host/root:ro
```

## Publishing to GitHub Container Registry

Push this repo to GitHub, then use the included workflow to build and publish images automatically from the default branch.

The image name is:

```text
ghcr.io/YOUR_ORG_OR_USER/archview:latest
```

## Notes

- The service is intentionally standard-library only.
- It is designed to run as a separate Docker deployment from the portfolio site.
- Update the frontend API URL to point to the deployed service domain instead of `localhost`.