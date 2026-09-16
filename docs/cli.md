# CLI reference

`scanner <scan|scan-cluster|backup|prune> [flags]`. `scanner -h` lists the subcommands and
`scanner <subcommand> -h` the flags; this page says what each one reaches. Nothing here changes
what [permissions.md](permissions.md) asks for.

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

## `scan`: an Azure subscription

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

| Flag | What it does |
|---|---|
| `--subscription` | the subscription id to scan (required) |
| `--api-url` | the console's base URL; omitted, the estate goes to stdout. Prefer `PARITY_API_URL`. Must be `https://` |
| `--api-key` | the key for the upload. Prefer `PARITY_API_KEY`: a flag is visible in the process list |
| `--exclude-groups` | comma-separated resource groups to leave out of the estate, normally the scanner's own. What was left out is recorded as one gap of reason `excluded` naming the groups and the count |
| `--include-platform-managed` | keep resources Azure creates and owns (`MC_`/`ME_` groups, NetworkWatcher); off by default because none of them can be restored |

## `scan-cluster`: a Kubernetes cluster, from inside it

```sh
scanner scan-cluster --cluster-id <ARM id of the AKS cluster>
```

Run it as a Job under the service account from
[`deploy/kubernetes/reader.yaml`](../deploy/kubernetes/reader.yaml): one `ClusterRole` with a
single verb, `list`, on the kinds the collector reads. `TestReaderManifestCoversEveryKind` holds
that file equal to the kinds in the code. `--api-url` and `--api-key` work as for `scan`.

## `backup` and `prune`: the one thing that writes

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

`scanner -h` also lists `closure` and `serve`. Both print `not implemented yet` and exit; the
work behind them is tracked in [issue #8](https://github.com/cloudparity/scanner/issues/8) and
[issue #9](https://github.com/cloudparity/scanner/issues/9).

## Deploy into your subscription

`deploy/azure/scanner.bicep` creates one resource group with a Container Apps job, a
user-assigned identity, and a storage account with a file share, and makes one grant outside
that group: Reader on the subscription, to that identity. The job runs once per trigger and
exits. [deploy/azure/README.md](../deploy/azure/README.md) is the walkthrough for both paths, file
share and console, including how the API key reaches the job as a Key Vault reference and never
as a template parameter.
