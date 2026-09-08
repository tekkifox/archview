# ArchView

ArchView is a separate Go service that collects Docker daemon data, container and image inventory, and Linux host metrics, then exposes them over JSON APIs and a small built-in dashboard.

## Repository layout

```text
.
  cmd/archview/main.go
  internal/service/server.go
  docker-compose.yml
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
DOCKER_HOST=tcp://socket-proxy:2375 \
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

Run the stack with the LinuxServer.io socket proxy and host mounts exposed read-only:

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
    ports:
      - "8080:8080"
    environment:
      PORT: "8080"
      DOCKER_HOST: "tcp://socket-proxy:2375"
      HOST_PROC: "/host/proc"
      HOST_SYS: "/host/sys"
      HOST_ROOT: "/host/root"
    volumes:
      - /proc:/host/proc:ro
      - /sys:/host/sys:ro
      - /:/host/root:ro
```

## Publishing to GitHub Container Registry

Push this repo to GitHub, then use the included workflow to build and publish images automatically from the default branch.

If you want the workflow to refresh a Portainer stack after publishing, add a repository secret named `PORTAINER_WEBHOOK_URL` with the Portainer stack webhook URL.

The image name is:

```text
ghcr.io/YOUR_ORG_OR_USER/archview:latest
```

## Notes

- The service is intentionally standard-library only.
- It is designed to run as a separate Docker deployment from the portfolio site.
- Update the frontend API URL to point to the deployed service domain instead of `localhost`.
- The Docker socket should only be mounted into `lscr.io/linuxserver/socket-proxy:latest`, not directly into ArchView.
