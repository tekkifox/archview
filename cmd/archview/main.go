package main

import (
	"log"
	"net/http"
	"os"
	"time"

	"github.com/tekkifox/archview/internal/service"
)

func main() {
	cfg := service.Config{
		Addr:       envOrDefault("PORT", "8080"),
		DockerAPI:  envOrDefault("DOCKER_API_VERSION", "v1.41"),
		DockerHost: envOrDefault("DOCKER_HOST", ""),
		DockerSock: envOrDefault("DOCKER_SOCKET", "/var/run/docker.sock"),
		HostProc:   envOrDefault("HOST_PROC", "/host/proc"),
		HostSys:    envOrDefault("HOST_SYS", "/host/sys"),
		HostRoot:   envOrDefault("HOST_ROOT", "/host/root"),
	}

	server := service.NewServer(cfg)
	httpServer := &http.Server{
		Addr:         ":" + cfg.Addr,
		Handler:      server.Routes(),
		ReadTimeout:  5 * time.Second,
		WriteTimeout: 15 * time.Second,
		IdleTimeout:  60 * time.Second,
	}

	log.Printf("archview listening on %s", httpServer.Addr)
	if cfg.DockerHost != "" {
		log.Printf("docker host: %s", cfg.DockerHost)
	} else {
		log.Printf("docker socket: %s", cfg.DockerSock)
	}
	log.Printf("host proc: %s", cfg.HostProc)

	if err := httpServer.ListenAndServe(); err != nil && err != http.ErrServerClosed {
		log.Fatalf("server failed: %v", err)
	}
}

func envOrDefault(key, fallback string) string {
	if value := os.Getenv(key); value != "" {
		return value
	}

	return fallback
}
