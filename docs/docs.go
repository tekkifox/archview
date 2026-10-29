// Package docs holds the OpenAPI specification embedded into the binary so the
// service can run as a self-contained container without copying files at
// runtime.
package docs

import _ "embed"

// OpenAPISpec is the raw OpenAPI document served from /docs/openapi.yaml.
//
//go:embed openapi.yaml
var OpenAPISpec []byte
