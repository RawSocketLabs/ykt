# ykt build/test/lint. Run from the repo root.
BINARY   := bin/ykt
PKG      := .
VERSION  ?= $(shell git describe --tags --always --dirty 2>/dev/null || echo dev)
LDFLAGS  := -s -w -X main.version=$(VERSION)
GOFLAGS  := -trimpath

.DEFAULT_GOAL := build

.PHONY: build
build: ## Build the binary for this platform (needs pcsc-lite-devel on Linux)
	go build $(GOFLAGS) -ldflags "$(LDFLAGS)" -o $(BINARY) $(PKG)

.PHONY: install
install: ## go install into GOBIN
	go install $(GOFLAGS) -ldflags "$(LDFLAGS)" $(PKG)

.PHONY: test
test: ## Run unit tests
	go test ./...

.PHONY: vet
vet: ## go vet
	go vet ./...

.PHONY: lint
lint: ## golangci-lint (install: https://golangci-lint.run)
	golangci-lint run

.PHONY: fmt
fmt: ## Format all Go files
	gofmt -w .

.PHONY: check
check: fmt vet test ## fmt + vet + test (pre-commit sanity)

.PHONY: cross
cross: ## Cross-compile windows/amd64 (pure syscall, no cgo)
	GOOS=windows GOARCH=amd64 CGO_ENABLED=0 go build $(GOFLAGS) -ldflags "$(LDFLAGS)" -o bin/ykt-windows-amd64.exe $(PKG)

.PHONY: clean
clean: ## Remove built binaries
	rm -rf bin/

.PHONY: help
help: ## List targets
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | \
	  awk 'BEGIN {FS = ":.*?## "}; {printf "  %-10s %s\n", $$1, $$2}'
