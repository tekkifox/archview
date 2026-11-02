package service

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestHandleArchitectureProjectSelection(t *testing.T) {
	handler := newResponseShapeServer(t).Routes()

	tests := []struct {
		name           string
		fullProjects   string
		target         string
		wantFull       bool
		wantProject    string
		wantContainers int
	}{
		{
			name:           "no project returns full host overview",
			target:         "/api/architecture",
			wantFull:       true,
			wantContainers: 1,
		},
		{
			name:           "empty project returns full host overview",
			target:         "/api/architecture?project=",
			wantFull:       true,
			wantContainers: 1,
		},
		{
			name:           "FULL_DOCKER_PROJECTS=1 returns full overview with a project supplied",
			fullProjects:   "1",
			target:         "/api/architecture?project=missing",
			wantFull:       true,
			wantContainers: 1,
		},
		{
			name:           "FULL_DOCKER_PROJECTS=1 returns full overview without a project",
			fullProjects:   "1",
			target:         "/api/architecture",
			wantFull:       true,
			wantContainers: 1,
		},
		{
			name:           "FULL_DOCKER_PROJECTS=true is case-insensitive and ignores whitespace",
			fullProjects:   "  TRUE  ",
			target:         "/api/architecture?project=missing",
			wantFull:       true,
			wantContainers: 1,
		},
		{
			name:           "FULL_DOCKER_PROJECTS=all selects every project",
			fullProjects:   "all",
			target:         "/api/architecture?project=missing",
			wantFull:       true,
			wantContainers: 1,
		},
		{
			name:           "explicit list matching the project still returns the full overview",
			fullProjects:   "demo",
			target:         "/api/architecture?project=demo",
			wantFull:       true,
			wantContainers: 1,
		},
		{
			name:           "explicit list leaves other projects scoped",
			fullProjects:   "demo",
			target:         "/api/architecture?project=missing",
			wantProject:    "missing",
			wantContainers: 0,
		},
		{
			name:           "unknown project without a full flag stays project scoped",
			target:         "/api/architecture?project=missing",
			wantProject:    "missing",
			wantContainers: 0,
		},
		{
			name:           "known project without a full flag stays project scoped",
			target:         "/api/architecture?project=demo",
			wantProject:    "demo",
			wantContainers: 1,
		},
		{
			name:           "alias uses the canonical project label when scoped",
			target:         "/api/architecture?project=image-mosaic",
			wantProject:    "travelling-site",
			wantContainers: 0,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Setenv("FULL_DOCKER_PROJECTS", tt.fullProjects)

			request := httptest.NewRequest(http.MethodGet, "https://archview.example"+tt.target, nil)
			recorder := httptest.NewRecorder()
			handler.ServeHTTP(recorder, request)

			if recorder.Code != http.StatusOK {
				t.Fatalf("status = %d, want 200 (body %s)", recorder.Code, recorder.Body.String())
			}

			var response map[string]any
			if err := json.Unmarshal(recorder.Body.Bytes(), &response); err != nil {
				t.Fatalf("decode response: %v", err)
			}

			environment, _ := response["environment"].(string)
			wantEnvironment := "static"
			if tt.wantFull {
				wantEnvironment = "docker"
			}
			if environment != wantEnvironment {
				t.Fatalf("environment = %q, want %q (body %s)", environment, wantEnvironment, recorder.Body.String())
			}

			extra, _ := response["extra"].(map[string]any)
			if tt.wantFull {
				if _, ok := extra["project"]; ok {
					t.Fatalf("full overview unexpectedly has a project in extra: %v", extra)
				}
			} else if got, _ := extra["project"].(string); got != tt.wantProject {
				t.Fatalf("extra.project = %q, want %q (body %s)", got, tt.wantProject, recorder.Body.String())
			}

			docker, _ := response["docker"].(map[string]any)
			containers, _ := docker["containers"].([]any)
			if len(containers) != tt.wantContainers {
				t.Fatalf("got %d containers, want %d (body %s)", len(containers), tt.wantContainers, recorder.Body.String())
			}

			if _, ok := response["telemetry"]; !ok {
				t.Fatalf("response is missing telemetry: %s", recorder.Body.String())
			}
			if endpoints, _ := response["endpoints"].([]any); len(endpoints) == 0 {
				t.Fatalf("response is missing endpoints: %s", recorder.Body.String())
			}
		})
	}
}
