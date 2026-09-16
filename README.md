# Cloud Parity scanner

[![verify](https://github.com/cloudparity/scanner/actions/workflows/verify.yml/badge.svg?branch=main)](https://github.com/cloudparity/scanner/actions/workflows/verify.yml)
[![lint](https://github.com/cloudparity/scanner/actions/workflows/lint.yml/badge.svg?branch=main)](https://github.com/cloudparity/scanner/actions/workflows/lint.yml)
[![govulncheck](https://github.com/cloudparity/scanner/actions/workflows/govulncheck.yml/badge.svg?branch=main)](https://github.com/cloudparity/scanner/actions/workflows/govulncheck.yml)
[![CodeQL](https://github.com/cloudparity/scanner/actions/workflows/codeql.yml/badge.svg?branch=main)](https://github.com/cloudparity/scanner/actions/workflows/codeql.yml)
[![OpenSSF Scorecard](https://api.scorecard.dev/projects/github.com/cloudparity/scanner/badge)](https://scorecard.dev/viewer/?uri=github.com/cloudparity/scanner)
[![Go version](https://img.shields.io/github/go-mod/go-version/cloudparity/scanner)](go.mod)
[![License](https://img.shields.io/github/license/cloudparity/scanner)](LICENSE)

The scanner is the part of Cloud Parity that runs inside your cloud. It reads an Azure
subscription, or a Kubernetes cluster from inside it, and writes what it finds as one JSON
document you can read. It is for the platform or security engineer who has to decide whether
that is safe to run on production.

You cannot rebuild what you cannot see. A recovery plan built from a dashboard is a guess: the
dashboard shows each resource on its own, and the outage takes them together. The scanner gives
you your whole subscription as one document, an *estate*: every resource, every reference
between them, what was redacted, and every place it could not look. From it the Cloud Parity
console gives you back a recovery plan, the order it rebuilds in, and a coverage verdict that
names what cannot be put back. The promise is short: metadata only; `scan` and `scan-cluster`
write nothing to your cloud; one built-in role; and you can read the code that keeps it, because
you are looking at it. The one subcommand that does write, `backup`, is a separate PostgreSQL
pipeline that cannot run unless you configure it: [docs/cli.md](docs/cli.md#backup-and-prune-the-one-thing-that-writes).

## See your recovery plan in three steps

1. **[Sign up at app.cloudparity.net/signup](https://app.cloudparity.net/signup)** with an email
   address and a company name, then mint a key on the *Run it yourself* page; it is listed under
   *Settings › API keys*.
2. Run the scanner, signed in as a principal that holds Reader on the subscription:

   ```sh
   az login
   export PARITY_API_URL=https://api.cloudparity.net
   export PARITY_API_KEY=<the key from step 1>
   scanner scan --subscription <subscription id>
   ```

   Leave the two variables unset and the estate goes to stdout instead, so you can read it
   before anything leaves. To run it as a job inside your subscription instead, with the key in
   a Key Vault you own, deploy the template: [deploy/azure/README.md](deploy/azure/README.md).
3. Open your plan in the console. Pick what you want back and see what comes with it, the order
   it rebuilds in, and what cannot be put back, named.

## What leaves your tenant, and what never does

By default, nothing: `scanner scan` prints the estate to stdout and exits, and the install
template writes it to a file share in a storage account you own. It uploads only when you set
`PARITY_API_URL`, only over `https://`, with the key in a request header and nowhere else.

| Leaves your tenant, when you say so | Never leaves, by construction |
|---|---|
| Each resource's configuration as the cloud API returned it, minus the values on the redaction list | Your data: not a blob, not a row, not a volume. The one data-plane role a scan ever asks for, Key Vault Reader, returns names and not values |
| The references between resources, as the ARM ids one document names | App settings, connection strings, administrator passwords, account keys: replaced before the document is written, each removal recorded with its path |
| A record of every redaction and every place the scan could not look, with the reason | Key Vault secret values: names and metadata only, from a call with no value field and a role that cannot get one |
| The subscription id, the resource ids, the scan time and the collector version | Kubernetes Secret values: stripped in code, each key recorded |

One built-in role does it: **Reader** at subscription scope, and the install template makes
exactly that one assignment on the subscription. For a cluster, one `ClusterRole` with a single
verb, `list`. Anything beyond that is optional and, when it is missing, recorded as a gap that
names the role that would close it. The manifest of every grant, what it unlocks and what we
will not ask for is [docs/permissions.md](docs/permissions.md); the redaction rules and the file
and line that enforce each promise are [docs/redaction.md](docs/redaction.md) and [SECURITY.md](SECURITY.md).

## Get it

Every release on the [Releases page](https://github.com/cloudparity/scanner/releases) carries a
static binary for linux/amd64, linux/arm64, darwin/arm64, darwin/amd64 and windows/amd64, and
the same commit is published as the container image the install template runs:

```sh
docker pull ghcr.io/cloudparity/scanner:<tag>       # e.g. ghcr.io/cloudparity/scanner:v0.1.0
```

Or build it yourself with Go 1.26 or newer:

```sh
git clone https://github.com/cloudparity/scanner && cd scanner
make build            # bin/scanner
```

## Verify a release

Every binary, the `SHA256SUMS` file and the image carry a signed build-provenance attestation
that proves it was built by this repository's workflow at the commit the release names. You
check it with the [GitHub CLI](https://cli.github.com) and no key of ours:

```sh
gh attestation verify scanner_v0.1.0_linux_amd64 --owner cloudparity                # a binary: substitute the file you downloaded
gh attestation verify oci://ghcr.io/cloudparity/scanner:v0.1.0 --owner cloudparity  # the image: substitute the tag
```

A good result says `✓ Verification succeeded!` and names `cloudparity/scanner` as the `Build repo`.
Anything else means the file or image is not the one this repository's workflow produced at that
tag: do not run it. How the attestations are made, how to check a mirrored copy, and how to
rebuild a byte-identical binary yourself: [docs/releases.md](docs/releases.md).

## How it works

The scanner discovers every resource in the subscription through Resource Graph and ARM, with
Reader and nothing more. It translates each one into a common shape and ships the cloud's own
document alongside, with the listed secret values replaced and each replacement recorded. It
links resources by the ids their documents name, so the console can rebuild them in the order
they depend on each other. And it emits one JSON document, with a gap for every place it could
not look, so the estate never claims more than it holds.

Read more:

- [docs/estate.md](docs/estate.md): the estate schema, where it goes, and what the binary talks to
- [docs/gaps.md](docs/gaps.md): every gap reason, what it means, and who fixes it
- [docs/redaction.md](docs/redaction.md): what is redacted, what is flagged, and why not a regex
- [docs/permissions.md](docs/permissions.md): every grant, what it unlocks, what we will not ask for
- [docs/cli.md](docs/cli.md): every subcommand and flag, building from source, and what `backup` and `prune` write
- [deploy/azure/README.md](deploy/azure/README.md), [deploy/kubernetes/reader.yaml](deploy/kubernetes/reader.yaml): the templates
- [docs/releases.md](docs/releases.md): attestations, reproducible builds, and how to check the tree yourself

## Report a problem

Vulnerabilities: [SECURITY.md](SECURITY.md). Everything else: open an issue.

## Contributing

Pull requests against `main`; what has to pass before one merges is in [CONTRIBUTING.md](CONTRIBUTING.md).

## License

Apache-2.0. See [LICENSE](LICENSE).
