# Contributing

Open a pull request against `main`. `verify` (`.github/workflows/verify.yml`) must pass before
it can merge: `gofmt`, `go vet` with and without the `docker` and `testbed` tags,
`go test ./...` and `go build ./...`. Nothing merges around it.

Before you push, `make hooks` once installs `pre-commit` and `pre-push` hooks that run the same
checks plus the race detector and a coverage floor of 85% on every collector, so you find out
locally. `make all` runs `fmt`, `vet`, `lint`, `test` and `build`.

Merging to `main` publishes `ghcr.io/cloudparity/scanner:latest` (`.github/workflows/image.yml`);
pushing a `v*` tag publishes the same image under that tag and a GitHub Release with the binaries
(`.github/workflows/release.yml`).

## Rules the tests enforce

- **Go 1.25 or newer.** `go.mod` is the source of truth; CI reads it.
- **Write the failing test first.** Table-driven tests; golden files for the JSON contract in
  `contract/testdata/`.
- **No network in unit tests.** Resource Graph, ARM, Key Vault and the Kubernetes API sit
  behind interfaces; tests use fakes. Tests that need a real PostgreSQL carry the `docker` build
  tag and run with `make test-docker`.
- **Read-only.** `scan` and `scan-cluster` never write to a customer's cloud. The one carve-out
  is `backup`, which creates its own replication slot; do not widen it.
- **Metadata only.** Never store or log a secret value. A new field that carries one goes on the
  redaction list in `agent/internal/collectors/azure/translate.go` with a reason, and a test.
- **Every gap names its remedy.** A resource the scanner could not read becomes a `Gap` with a
  reason and, for `permission-denied`, the role that would close it.
- **`contract/` is the wire format.** Change it deliberately, with the golden files.
- Wrap errors with context (`fmt.Errorf("...: %w", err)`). Library code does not panic;
  `os.Exit` only in `main`.
- Commit messages: imperative and scoped, e.g. `scan: paginate resource graph`.

## Reporting a vulnerability

Not in a pull request or an issue. See [SECURITY.md](SECURITY.md).
