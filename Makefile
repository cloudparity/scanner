# scanner — dev tasks. Run from repo root (single Go module).
.PHONY: all hooks fmt vet lint test test-race test-docker test-e2e fuzz cover build run tidy
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

# A missing linter is a failure, not a skip. The previous `&& run || echo skipping` fired the
# echo when golangci-lint was installed and FOUND SOMETHING too, so `make all` could never fail
# on a lint finding. The set it runs is .golangci.yml; a finding is fixed at the line, not here.
lint:
	@command -v golangci-lint >/dev/null || { \
	  echo "golangci-lint is not installed. Install it: go install github.com/golangci/golangci-lint/v2/cmd/golangci-lint@latest"; \
	  exit 1; \
	}
	golangci-lint run ./...

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

# Every native fuzz target (func FuzzXxx in a _test.go), each for FUZZTIME. `go test -fuzz`
# runs exactly one target per invocation, so this discovers them and loops; the same discovery
# drives .github/workflows/fuzz.yml, which runs them weekly. A crasher is written under the
# package's testdata/fuzz/<Fuzzer>/ and is a regression test from then on: commit it with the
# fix, never delete it to make the run green. One target, longer:
#   go test -run='^$' -fuzz=FuzzParseARMID -fuzztime=5m ./agent/internal/collectors/azure/
FUZZTIME ?= 30s
fuzz:
	@set -e; go test -list '^Fuzz' ./... | awk ' \
	    /^Fuzz/ { names[n++] = $$1 } \
	    /^ok / { for (i = 0; i < n; i++) printf "%s %s\n", $$2, names[i]; n = 0 }' \
	| while read -r pkg fuzzer; do \
	    echo "== $$fuzzer ($$pkg) for $(FUZZTIME)"; \
	    go test -run='^$$' -fuzz="^$$fuzzer\$$" -fuzztime=$(FUZZTIME) "$$pkg"; \
	done

cover:
	go test ./agent/internal/collectors/azure/ -coverprofile=/tmp/scanner-cover.out
	go tool cover -func=/tmp/scanner-cover.out | tail -1
	@echo "detail: go tool cover -html=/tmp/scanner-cover.out"

build:
	go build -o bin/scanner ./agent/cmd/scanner

run:
	go run ./agent/cmd/scanner $(ARGS)
