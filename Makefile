.PHONY: test build run docker-build

test:
	go test ./...

build:
	mkdir -p bin
	go build -o bin/checker ./cmd/checker

run:
	mkdir -p build
	ATTEMPT_ID=local SESSION_NAMESPACE=lab-local TEST_PATH=smoke \
		go run ./cmd/checker -output build/result.json

docker-build:
	docker build -t ghcr.io/cms-lab-core/cms-labs-checker:local .
