# Security

## Report a vulnerability

Email **security@cloudparity.net**. Do not open a public issue for a vulnerability.

Include what you found, the commit or release you found it in, and how to reproduce it. You get
an acknowledgement within three business days, and a fix or a stated reason before any public
disclosure. Tell us if you have a disclosure date in mind.

## Scope

In scope: everything in this repository. The scanner binary (`agent/cmd/scanner`), the packages
it links, the install template (`deploy/azure/`), the Kubernetes manifest (`deploy/kubernetes/`),
the container images built from the two Dockerfiles, and the release workflow.

Particularly in scope, because they are the promises the product rests on:

- a way for `scanner scan` or `scanner scan-cluster` to write to a customer's cloud
- a secret value reaching the estate, the log, or an error message
- the upload going anywhere but the configured `https://` URL, or the API key going anywhere but
  the request header
- the install template granting more than Reader on the subscription
- a way to make the binary contact a host not listed in the README

Out of scope: the Cloud Parity console and API (report those to the same address; they are not
in this repository), and findings that need a credential the scanner is never given.

## The metadata-only promise, and where it is enforced

The scanner ships configuration, never contents and never secret values. These are the lines
that make that true. If you can get past one of them, that is a report.

| Promise | Enforced at |
|---|---|
| The upload goes to `https://` only, or not at all | `agent/internal/upload/upload.go:43-48`: `New` returns an error for any URL not starting `https://`, localhost included, and `scan` checks this before it reads anything |
| The API key is in a header, never the URL, the body, or an error | `agent/internal/upload/upload.go:27` (`KeyHeader`), `upload.go:87` (the one place it is set); `upload_test.go` asserts it appears in neither the URL, the body nor any error text |
| Known secret-bearing fields are removed before the document is written, and each removal is recorded | `agent/internal/collectors/azure/translate.go:278-285` (`redactionRules`), applied in `redactedDocument` at `translate.go:292`; every hit becomes a `contract.Redaction` on the resource (`contract/estate.go:111-113`) |
| Kubernetes Secret values never leave the cluster | `agent/internal/collectors/k8s/translate.go:274` (`scrub`) strips `data` and `stringData` and records each key as a redaction; `deploy/kubernetes/reader.yaml` grants `list` and no write verb |
| A field that looks like a credential and was not on the list is flagged, not silently shipped | `agent/internal/collectors/azure/screen.go:68` and `agent/internal/collectors/k8s/screen.go:77` add a gap of reason `unscreened` (`contract/estate.go:244`) naming the paths |
| Key Vault: names and metadata, never a value | `agent/internal/collectors/azure/keyvault.go:56`: the struct the list response decodes into has no value field; `keyvault.go:306` is the only request, a `GET` on the list endpoint, which returns none |
| `scan` and `scan-cluster` make no write call | `grep -rn 'http.Method\(Post\|Put\|Delete\|Patch\)' --include='*.go' --exclude='*_test.go' .` returns only the upload client and the `backup`/`prune` pipeline; the collectors under `agent/internal/collectors/` contain none |
| The install template grants one role on the subscription | `deploy/azure/scanner.bicep:107` is the only `roleDefinitions` reference in the subscription-scope template: Reader, `acdd72a7-3385-48ef-bd42-f606fba81ae7`. The one other assignment in the tree, AcrPull at `deploy/azure/scanner-resources.bicep:70`, is scoped to a registry you own and made only when you pass `registryResourceId` to mirror the image |
| The shipped container has no shell | root `Dockerfile`: `FROM scratch`, `USER 65534:65534`, one binary and a CA bundle |

Anything the scanner could not read is recorded as a gap with a reason (`contract/estate.go:198-244`)
rather than dropped, so an estate never claims more than it holds.

## What the `backup` subcommand does that `scan` does not

`scanner backup` writes: it creates one logical replication slot on the PostgreSQL server it is
pointed at, puts chunks into a blob container, and triggers an Azure Backup on-demand backup and
restore-as-files on one named backup instance (`agent/internal/backup/postgres/controlplane.go:189,240`;
`agent/internal/backup/store/blob.go:105`). `scanner prune --apply` deletes blobs
(`store/blob.go:440`). Neither runs unless invoked with its own flags. A vulnerability that lets
`scan` reach any of that code, or lets `backup` write anywhere other than the container and the
backup instance it was given, is in scope.

## Supported versions

The latest release. Report against `main` if you can.
