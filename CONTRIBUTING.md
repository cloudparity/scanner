# Contributing

Open a pull request against `main`. `verify` (`.github/workflows/verify.yml`) must pass before
it can merge: `gofmt`, `go vet` with and without the `docker` and `testbed` tags,
`go test ./...` (with a Bicep compiler on `PATH`, so the install template is compiled and
checked too) and `go build ./...`. Nothing merges around it: `main` is protected so that only a
pull request can change it, only after `verify` has passed on it, and that applies to
administrators as well. You can read the setting yourself:
`gh api repos/cloudparity/scanner/branches/main/protection`.

Three more workflows run on every pull request and every push to `main`, and their badges sit
at the top of README.md: `lint` (`.github/workflows/lint.yml`, golangci-lint at the version
pinned there with `.golangci.yml`), `govulncheck` (`.github/workflows/govulncheck.yml`) and
`CodeQL` (`.github/workflows/codeql.yml`). Each fails on a finding: the linter on any issue in
its set, govulncheck on any advisory whose vulnerable symbol this code reaches, and CodeQL on
any open code-scanning alert for the ref it analysed (a step after the analysis asks the API,
because the upload itself succeeds whether or not it found anything). A finding is fixed at the
line, not excluded; a CodeQL alert that is a genuine false positive is dismissed in the Security
tab with a reason, which is the same rule in that tool's form. Whether `main` also requires
these three before a merge is part of the branch-protection setting above; read it rather than
assume.

Before you push, `make hooks` once installs `pre-commit` and `pre-push` hooks that run the same
checks plus the race detector and a coverage floor of 85% on every collector, so you find out
locally. Those two are stricter than CI and run only in the hook. `make all` runs `fmt`, `vet`,
`lint`, `test` and `build`; `lint` needs [golangci-lint](https://golangci-lint.run/) v2 on your
PATH and fails if it is missing, because a linter that is skipped when absent is a linter nobody
runs.

Merging to `main` publishes `ghcr.io/cloudparity/scanner:latest` (`.github/workflows/image.yml`);
pushing a `v*` tag publishes the same image under that tag and a GitHub Release with the binaries
(`.github/workflows/release.yml`). Both workflows run `go test ./...` on the exact commit they
publish before they build anything, so a tag on a commit that never went through `verify` still
cannot publish a failing build.

## Fuzzing

The parsers that read what a cloud returned - the ARM resource-id parser and the reference
recogniser in `agent/internal/collectors/azure/`, the redaction and screening walks over a
Resource Graph document, the hostname tokenizer, the Kubernetes object translation in
`agent/internal/collectors/k8s/`, and the `contract.Estate` JSON round trip - each have a
native Go fuzz target (`func FuzzXxx(f *testing.F)`) beside their unit tests. The unit tests
pin what a parser says about well-formed input; the fuzz targets pin what it must never do on
any input: panic, produce an id that fails its own normalization, record a redaction that did
not happen, mutate the row it was handed, or give a different answer to the same bytes twice.

`go test ./...` runs every target over its seed corpus and every crasher ever found, so they
are part of `verify` like any other test. The search for new crashers is a time budget rather
than a fixed set of cases, so it runs separately: `make fuzz` runs every target for 30 seconds
(`make fuzz FUZZTIME=2m` for longer), and `fuzz` (`.github/workflows/fuzz.yml`) runs each one
for 60 seconds weekly and on demand. To run one target for longer:

```sh
go test -run='^$' -fuzz=FuzzParseARMID -fuzztime=5m ./agent/internal/collectors/azure/
```

A failing input is written to the package's `testdata/fuzz/<FuzzName>/` and is a plain test
case from then on. Commit it, with a name that says what it found, together with the fix -
never delete it or loosen the invariant to make the run green. A fuzzer finding a panic in a
parser that reads a customer's cloud is a real finding, and the entries already there record
the ones it has made. When you add a parser that takes untrusted bytes or strings, add a
target with it; seed it from the unit tests' cases and assert the invariants that matter,
not the outputs.

## Rules the tests enforce

- **Go 1.26 or newer.** `go.mod` is the source of truth; CI reads it.
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
