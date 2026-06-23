export CGO_ENABLED := 0

.PHONY: all build test lint lint-install doctor e2e caddy-test smoke-test qa-test check-imports check-todos systemd-check clean

all: lint check-imports check-todos test build

build:
	go build -trimpath -ldflags="-s -w" ./...

test:
	CGO_ENABLED=1 go test -race -count=1 ./...

lint:
	go vet ./...
	golangci-lint run ./...

# staticcheck v0.6.0, golangci-lint v1.64.8
lint-install:
	go install honnef.co/go/tools/cmd/staticcheck@v0.6.0
	go install github.com/golangci/golangci-lint/cmd/golangci-lint@v1.64.8

doctor:
	@echo "Checking prerequisites..."
	@go version | grep -q 'go1\.\(2[2-9]\|[3-9][0-9]\)' || { echo "FAIL: Go >= 1.22 required"; exit 1; }
	@command -v golangci-lint >/dev/null 2>&1 || { echo "FAIL: golangci-lint not found (run: make lint-install)"; exit 1; }
	@command -v staticcheck >/dev/null 2>&1 || { echo "FAIL: staticcheck not found (run: make lint-install)"; exit 1; }
	@echo "All prerequisites OK."

e2e: build
	@sh test/e2e/roundtrip.sh

caddy-test:
	@sh test/caddy/prefix_strip_test.sh

smoke-test: build
	@sh test/smoke/10x_10mib.sh

qa-test: build
	@sh test/smoke/qa-roundtrip.sh

check-imports:
	@sh scripts/check_imports.sh

check-todos:
	@sh scripts/check_todos.sh

systemd-check:
	@command -v systemd-analyze >/dev/null 2>&1 || { echo "SKIP: systemd-analyze not found"; exit 0; }
	systemd-analyze verify deploy/systemd/deaddrop-relay.service

test-derive: ## TEST-ONLY: build the local-laptop derivation wrapper
	go build -trimpath -o ./tools/test-derive/test-derive ./tools/test-derive

clean:
	go clean ./...
	rm -rf bin/
