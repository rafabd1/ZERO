APP := zero

.PHONY: build test tidy run-migrate

build:
	go build -o bin/$(APP) ./cmd/zero

test:
	go test ./...

tidy:
	go mod tidy

run-migrate:
	go run ./cmd/zero migrate up
