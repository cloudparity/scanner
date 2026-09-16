# Cloud Parity scanner

[![verify](https://github.com/cloudparity/scanner/actions/workflows/verify.yml/badge.svg?branch=main)](https://github.com/cloudparity/scanner/actions/workflows/verify.yml)
[![lint](https://github.com/cloudparity/scanner/actions/workflows/lint.yml/badge.svg?branch=main)](https://github.com/cloudparity/scanner/actions/workflows/lint.yml)
[![govulncheck](https://github.com/cloudparity/scanner/actions/workflows/govulncheck.yml/badge.svg?branch=main)](https://github.com/cloudparity/scanner/actions/workflows/govulncheck.yml)
[![CodeQL](https://github.com/cloudparity/scanner/actions/workflows/codeql.yml/badge.svg?branch=main)](https://github.com/cloudparity/scanner/actions/workflows/codeql.yml)
[![OpenSSF Scorecard](https://api.scorecard.dev/projects/github.com/cloudparity/scanner/badge)](https://scorecard.dev/viewer/?uri=github.com/cloudparity/scanner)
[![Go version](https://img.shields.io/github/go-mod/go-version/cloudparity/scanner)](go.mod)
[![License](https://img.shields.io/github/license/cloudparity/scanner)](LICENSE)

The scanner is the part of Cloud Parity that runs inside your cloud. It reads the configuration
of an Azure subscription, or of a Kubernetes cluster from inside it, and writes one JSON document
called an *estate*: every resource, the references between them, what was redacted, and every
place it could not look. The Cloud Parity console reads estates to work out what a region loss
would take with it and what it would take to rebuild.

It reads. It does not restore, and `scanner scan` does not write anything to your cloud. The one
subcommand that writes, `backup`, is described in its own section below so you do not have to
find out from the code.

## What it needs

One built-in role: **Reader** at subscription scope. The install template
(`deploy/azure/scanner.bicep`) makes exactly that one role assignment. Anything beyond it is
optional, opt-in, and recorded as a gap in the estate when it is missing. The full table is
[docs/permissions.md](docs/permissions.md).

For a cluster, one `ClusterRole` with a single verb, `list`, on the kinds the collector reads:
[deploy/kubernetes/reader.yaml](deploy/kubernetes/reader.yaml). A test
(`TestReaderManifestCoversEveryKind`) holds that file equal to the kinds in the code.

## What leaves your tenant

By default, nothing. `scanner scan` prints the estate to stdout and exits. The install template
writes it to a file share in a storage account you own. Read it before you send it anywhere.

If you set `PARITY_API_URL` (or `--api-url`), the scanner POSTs the estate to
`$PARITY_API_URL/v1/scans` with the key from `PARITY_API_KEY` in a request header. The URL must be
`https://`; `agent/internal/upload/upload.go:43-48` refuses anything else, including localhost.

The estate carries each resource's configuration document as the cloud API returned it, minus
the values on a redaction list. Both halves of that sentence matter:

- **Redacted, and recorded.** App Service app settings and connection strings, database
  administrator passwords, and storage/account keys (`properties.*.primaryKey`, `secondaryKey`,
  `accessKey`) are replaced before the document is written, and each removal is listed in
  `resource.redactions` with its path and reason. The list is
  `agent/internal/collectors/azure/translate.go:278-285`. Kubernetes Secret values (`data`,
  `stringData`) are stripped at the same boundary: `agent/internal/collectors/k8s/translate.go:274`.
- **Flagged, not redacted.** Anything that looks like a credential but is not on the list ships
  as-is and the resource gets a gap of reason `unscreened` naming the field paths
  (`agent/internal/collectors/azure/screen.go`, `agent/internal/collectors/k8s/screen.go`). An
  Application Insights `InstrumentationKey` is the common case. The scanner does not guess: a
  regex sweep would also blank `keyVaultUri` and `sshPublicKey`, which are the join keys the
  dependency graph is built from. If a flagged field is a secret to you, tell us and it moves to
  the list.
- **Key Vault: names, never values.** The collector lists secret names and metadata from the
  vault data plane. The call it makes (`GET {vault}/secrets`) has no value field, and the role it
  asks for, Key Vault Reader, does not include `getSecret`. `agent/internal/collectors/azure/keyvault.go:56`
  is the struct the response is decoded into; it has no value field to decode into.

The endpoints the binary connects to during `scan`: `login.microsoftonline.com` (token),
`management.azure.com` (Resource Graph and ARM), `*.vault.azure.net` (secret names, when the
role is granted), and `PARITY_API_URL` if you set it. During `scan-cluster`: the cluster's own
API server, `login.microsoftonline.com` when the token for it comes from Entra rather than the
pod's projected service-account token, and `PARITY_API_URL` if set. Nothing else.

## Get it

Every release on the [Releases page](https://github.com/cloudparity/scanner/releases) carries a
static binary for linux/amd64, linux/arm64, darwin/arm64, darwin/amd64 and windows/amd64, plus a
`SHA256SUMS` file, each with a signed build-provenance attestation. Download the one for your
platform and check it (see *Verify a release*).

The same commit is published as a container image, the one `deploy/azure/scanner.bicep` runs:

```sh
docker pull ghcr.io/cloudparity/scanner:<tag>       # e.g. ghcr.io/cloudparity/scanner:v0.1.0
```

`:latest` follows `main`, and every push to `main` is also tagged with its commit sha. Pin a
release tag, or the digest the release notes name, for anything you run more than once.

## Build from source

Go 1.26 or newer (`go.mod` says `go 1.26.0`; `golang.org/x/crypto` v0.56.0, which fixes the last of
the open advisories, requires it, and 1.25 fails with `requires go >= 1.26.0`). `go.mod` also pins
`toolchain go1.26.8`, the patch release that carries the standard-library fixes `govulncheck`
reports against 1.26.0, so an older `go` on your machine (or in CI) fetches it and builds with it.

```sh
make build            # bin/scanner
go build ./agent/cmd/scanner
```

As a container, from the root `Dockerfile` (a `scratch` image: one static binary and a
certificate bundle, running as uid 65534):

```sh
docker build --platform linux/amd64 --build-arg TARGETARCH=amd64 -t scanner .
```

`deploy/azure/Dockerfile` is the Alpine variant the Container Apps job uses, because that job
needs a shell to redirect stdout onto a mounted file share.

## Run

Sign in as the principal that holds Reader on the subscription, then scan:

```sh
az login
scanner scan --subscription <subscription id> > estate.json
```

Credentials come from `DefaultAzureCredential`: the `az` login, environment variables, a
managed identity, or a workload identity, in that order of what is present. The scanner never
takes a credential as a flag.

To send the estate to the console instead of stdout:

```sh
export PARITY_API_URL=https://api.cloudparity.net
export PARITY_API_KEY=<a key minted in the console>
scanner scan --subscription <subscription id>
```

Use the environment for the key, not `--api-key`: a flag is visible in the process list.

Flags for `scan`: `--exclude-groups` (resource groups to leave out, normally the scanner's own),
`--include-platform-managed` (keep `MC_`/`ME_` groups and NetworkWatcher; off by default because
none of them can be restored).

From inside a cluster: `scanner scan-cluster --cluster-id <ARM id of the AKS cluster>`, as a Job
running under the service account from `deploy/kubernetes/reader.yaml`.

## Deploy into your subscription

`deploy/azure/scanner.bicep` creates one resource group with a Container Apps job, a
user-assigned identity, and a storage account with a file share, and makes one grant outside
that group: Reader on the subscription, to that identity. The job runs once per trigger and
exits. [deploy/azure/README.md](deploy/azure/README.md) is the walkthrough for both paths, file
share and console, including how the API key reaches the job as a Key Vault reference and never
as a template parameter.

## The `backup` and `prune` subcommands

The same binary carries a PostgreSQL backup pipeline. It is off unless you run it, and it needs
its own configuration; nothing in `scan` touches it. Read this before you do:

- `scanner backup` connects to a PostgreSQL Flexible Server as a role with `REPLICATION`,
  creates **one logical replication slot** on that server (the only object the scanner ever
  creates on a database), streams changes, and writes chunks to a blob container you name. It
  also calls Azure Backup's Data Protection API to trigger an on-demand backup and a restore-as-
  files of the backup instance you name (`agent/internal/backup/postgres/controlplane.go`). Those
  are writes to your subscription, and they need permissions Reader does not grant; the header
  comments in `agent/cmd/scanner/backup.go` list every flag and what it reaches. The slot is
  dropped on every exit path the process controls; a drop that fails exits non-zero and says so.
- `scanner prune` reads the container and prints what a retention policy would delete. It
  deletes nothing unless you pass `--apply`.

If you only want the estate, do not configure these and they cannot run.

## Verify a release

Every release on the Releases page carries the binaries and a `SHA256SUMS` file. Check the
binary against it before you run it:

```sh
sha256sum -c SHA256SUMS --ignore-missing      # macOS: shasum -a 256 -c SHA256SUMS --ignore-missing
```

That proves the download is intact. To prove it was *built by this repository's workflow at
the commit the release names*, and not by whoever holds the Releases page, every binary, the
`SHA256SUMS` file and the container image carry a signed build-provenance attestation
([GitHub artifact attestations](https://docs.github.com/en/actions/security-for-github-actions/using-artifact-attestations/using-artifact-attestations-to-establish-provenance-for-builds):
a SLSA provenance statement, signed with a short-lived Sigstore certificate the workflow obtains
through OIDC, so there is no signing key to steal). You need the [GitHub CLI](https://cli.github.com)
2.49 or later, signed in (`gh auth login`); no other tool, and no key of ours.

A binary (substitute the file you downloaded):

```sh
gh attestation verify scanner_v0.1.0_linux_amd64 --owner cloudparity
```

The image for a tag (substitute the tag):

```sh
gh attestation verify oci://ghcr.io/cloudparity/scanner:v0.1.0 --owner cloudparity
```

A good result says `✓ Verification succeeded!` and, below it, one matching attestation whose
`Build repo` is `cloudparity/scanner` and whose `Build workflow` is
`.github/workflows/release.yml@refs/tags/<tag>` for a binary or
`.github/workflows/image.yml@refs/tags/<tag>` for the image. Anything else, including
`✗ Verification failed` or `Error: no attestations found`, means the file or image is not the
one this repository's workflow produced at that tag: do not run it. (Without a terminal, in a
script, a good result prints nothing and exits 0.) `--owner cloudparity` accepts an attestation
from any repository in the organisation; `--repo cloudparity/scanner` narrows it to this one.
Each release also attaches the binaries' attestation as `scanner_<tag>.sigstore.json`;
`gh attestation verify <file> --bundle scanner_<tag>.sigstore.json --owner cloudparity` checks
against that copy instead of the one GitHub's API serves. The image's attestation is pushed to
ghcr.io beside the image as well, so it follows a mirror.

The release notes name the commit and the Go version each binary was built from, and the digest
of the container image built from the same commit. A binary you build yourself from a clean
checkout of that commit, with that Go version and the same command
(`CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" ./agent/cmd/scanner`), is byte-identical to
the released one; the checkout matters because Go stamps the commit into the binary
(`go version -m scanner` shows it). The image's binary is built from the same source with the
same flags but from a context without `.git`, so it carries no stamp and hashes differently.
The workflows that produce them are `.github/workflows/release.yml` and
`.github/workflows/image.yml`; both run `go test ./...` on the tagged commit before they build,
and a release is not published until the image for the tag is anonymously pullable and both
the binaries and the image have passed the two `gh attestation verify` commands above, run by
the workflow itself.

## Check the tree yourself

- `go list -deps ./agent/cmd/scanner | grep "$(go list -m)/"` lists every package in this
  repository the binary links.
- `grep -rn 'http.Method\(Post\|Put\|Delete\|Patch\)' --include='*.go' --exclude='*_test.go' .`
  finds every non-GET call: the estate upload, and the `backup`/`prune` pipeline described above.
- `make all` runs `gofmt`, `go vet`, the linter, the tests and the build. CI
  (`.github/workflows/verify.yml`) runs `gofmt`, `go vet`, `go test ./...` (with a pinned Bicep
  compiler on `PATH`, so the install template is compiled and checked) and `go build ./...` on
  every pull request and every push to `main`, with no Docker daemon and no cloud credential.
  `main` accepts only pull requests that passed it, administrators included:
  `gh api repos/cloudparity/scanner/branches/main/protection`.
- The badges at the top of this page are the live status of a workflow on `main`, each linked
  to its run history, and nothing else: `lint` (`.github/workflows/lint.yml`, golangci-lint with
  `.golangci.yml`, a finding fails it), `govulncheck` (`.github/workflows/govulncheck.yml`, an
  advisory whose vulnerable symbol this code reaches fails it) and `CodeQL`
  (`.github/workflows/codeql.yml`, which fails while any CodeQL alert for the analysed ref is
  open, not merely when the upload fails). The OpenSSF Scorecard badge is that project's own
  weekly read of this repository (`.github/workflows/scorecard.yml` publishes it); the Go
  version and license badges are read from `go.mod` and `LICENSE`.

## Report a problem

Vulnerabilities: [SECURITY.md](SECURITY.md). Everything else: open an issue.

## License

Apache-2.0. See [LICENSE](LICENSE).
