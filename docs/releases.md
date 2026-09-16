# Releases: what is published, and how to prove it

Every release on the [Releases page](https://github.com/cloudparity/scanner/releases) carries a
static binary for linux/amd64, linux/arm64, darwin/arm64, darwin/amd64 and windows/amd64, plus a
`SHA256SUMS` file, each with a signed build-provenance attestation. The same commit is published
as a container image, the one `deploy/azure/scanner.bicep` runs: `ghcr.io/cloudparity/scanner:<tag>`.
`:latest` follows `main`, and every push to `main` is also tagged with its commit sha. Pin a
release tag, or the digest the release notes name, for anything you run more than once.

## Verify a release

Every release on the Releases page carries the binaries and a `SHA256SUMS` file. Check the
binary against it before you run it:

```sh
sha256sum -c SHA256SUMS --ignore-missing      # macOS: shasum -a 256 -c SHA256SUMS --ignore-missing
```

That proves the download is intact. To prove it was *built by this repository's workflow at
the commit the release names*, and not by whoever holds the Releases page, every binary, the
`SHA256SUMS` file and the container image each carry their own signed build-provenance attestation
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
Each release also attaches every file's attestation beside it as a Sigstore bundle,
`<file>.sigstore.json` (`scanner_v0.1.0_linux_amd64.sigstore.json`, `SHA256SUMS.sigstore.json`,
and so on); `gh attestation verify <file> --bundle <file>.sigstore.json --owner cloudparity`
checks against that copy instead of the one GitHub's API serves, so a mirror of the Releases
page stays verifiable. `scanner_<tag>.intoto.jsonl` is the same six bundles in one file, one per
line, and `--bundle scanner_<tag>.intoto.jsonl` works for any of the files: `gh` tries each line
and accepts the one whose subject is the file. The image's attestation is pushed to ghcr.io
beside the image as well, so it follows a mirror.

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
the binaries and the image have passed the two `gh attestation verify` commands above (each
file against the API, against its own `.sigstore.json` and against the `.intoto.jsonl`), run by
the workflow itself.

## Check the tree yourself

- `go list -deps ./agent/cmd/scanner | grep "$(go list -m)/"` lists every package in this
  repository the binary links.
- `grep -rn 'http.Method\(Post\|Put\|Delete\|Patch\)' --include='*.go' --exclude='*_test.go' .`
  finds every non-GET call: the estate upload, and the `backup`/`prune` pipeline described in
  [cli.md](cli.md).
- `make all` runs `gofmt`, `go vet`, the linter, the tests and the build. CI
  (`.github/workflows/verify.yml`) runs `gofmt`, `go vet`, `go test ./...` (with a pinned Bicep
  compiler on `PATH`, so the install template is compiled and checked) and `go build ./...` on
  every pull request and every push to `main`, with no Docker daemon and no cloud credential.
  `main` accepts only pull requests that passed it, administrators included:
  `gh api repos/cloudparity/scanner/branches/main/protection`.
- The badges at the top of [README.md](../README.md) are the live status of a workflow on `main`, each linked
  to its run history, and nothing else: `lint` (`.github/workflows/lint.yml`, golangci-lint with
  `.golangci.yml`, a finding fails it), `govulncheck` (`.github/workflows/govulncheck.yml`, an
  advisory whose vulnerable symbol this code reaches fails it) and `CodeQL`
  (`.github/workflows/codeql.yml`, which fails while any CodeQL alert for the analysed ref is
  open, not merely when the upload fails). The OpenSSF Scorecard badge is that project's own
  weekly read of this repository (`.github/workflows/scorecard.yml` publishes it); the Go
  version and license badges are read from `go.mod` and `LICENSE`.
