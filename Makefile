build:
	go build ./cmd/archview

run:
	go run ./cmd/archview

test:
	go test ./...

fmt:
	gofmt -w ./cmd ./internal ./docs

vet:
	go vet ./...

.PHONY: build run test fmt vet