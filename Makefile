# scanner — dev tasks. Run from repo root (single Go module).
.PHONY: all hooks fmt vet lint test test-race test-docker test-e2e cover build run tidy
all: fmt vet lint test build

hooks:
	git config core.hooksPath .githooks
	@chmod +x .githooks/* 2>/dev/null || true
	@echo "git hooks installed (core.hooksPath=.githooks) — runs on commit and push"

fmt:
	gofmt -l -w .
	go mod tidy

vet:
	go vet ./...
	# Build-tagged files are invisible to the line above, so they rot in silence. Vetting needs no
	# Docker daemon — only the compiler — so this stays in the fast gate while the tests do not.
	# `testbed` is here for a stronger version of the same reason: that test is never RUN by anyone
	# (it fills a real Azure disk), so type-checking it is the only thing standing between it and rot.
	go vet -tags docker,testbed ./...

lint:
	@command -v golangci-lint >/dev/null && golangci-lint run ./... || echo "golangci-lint not installed — skipping (install for full checks)"

test:
	go test ./...

# What the git hooks run. -race because the collector pages a remote API.
test-race:
	go test -race ./...

# Throwaway Postgres containers: proves the version branch against real 14 and 18 servers and
# proves a base copy against a real server. Needs Docker and pulls images, which is why `all`
# leaves it out. Every container is removed by a t.Cleanup, including when the test fails.
test-docker:
	go test -tags docker ./agent/internal/backup/postgres/ -v

# The pipeline suite: canned Resource Graph pages -> real Collect -> Estate.
test-e2e:
	go test ./agent/internal/collectors/azure/ -run '^TestE2E' -v

cover:
	go test ./agent/internal/collectors/azure/ -coverprofile=/tmp/scanner-cover.out
	go tool cover -func=/tmp/scanner-cover.out | tail -1
	@echo "detail: go tool cover -html=/tmp/scanner-cover.out"

build:
	go build -o bin/scanner ./agent/cmd/scanner

run:
	go run ./agent/cmd/scanner $(ARGS)
