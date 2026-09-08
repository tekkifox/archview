build:
	go build ./cmd/archview

run:
	go run ./cmd/archview

test:
	go test ./...

.PHONY: build run test