# The estate

`scanner scan` writes one JSON document called an *estate*: every resource in the subscription,
the references between them, what was redacted, and every place it could not look. The Cloud
Parity console reads estates to work out what a region loss would take with it and what it
would take to rebuild. The Go types that are the wire format live in `contract/estate.go`; this
page is the reading guide.

The scanner is deliberately dumb. It reads a cloud exhaustively, restates the identifying facts
in one vocabulary, and ships the untouched source document alongside. It makes no judgments: no
recovery strategy, no hard-versus-soft dependency call, no guess at what a field means. Every
one of those is made server-side from the document, which is what lets an improvement in the
console re-derive every stored estate with no re-scan.

## Shape

```
{
  "contractVersion": 1,
  "scan":         { provider, account, scannedAt, collector, resourceCount, gaps[] },
  "resources":    [ { provider, id, parentId, type, name, account, group, region, tags,
                      document, redactions[] } ],
  "dependencies": [ { from, to, via, resolvedTo, resolution } ]
}
```

`contractVersion` is the wire-format version. Changes within a version are additive only; a
breaking change bumps it.

### `scan`

Who scanned what, when, and what they could not reach. `provider` is `azure` or `k8s`;
`account` is the scanned boundary (subscription id, or the cluster's ARM id); `scannedAt` is
RFC 3339; `collector` is the collector name and version, e.g. `azure/0.1.0`; `resourceCount` is
the length of `resources`. `gaps` is everything the scan could not read, and why. An empty list
is a claim that the scan was complete; it is not a default. The reasons are in [gaps.md](gaps.md).

### `resources[]`

One entry per thing found: its identity in the contract's words, plus the cloud's own document
untouched.

- `id` is the cloud's own identifier (ARM resource id; Kubernetes `apiVersion/kind/namespace/name`),
  normalized so that string equality is the correct identity test for that cloud: Azure ids are
  lowercased because ARM's own casing is inconsistent, Kubernetes ids are verbatim because they
  are case-sensitive. The original spelling survives in `document`.
- `parentId` is the id of the resource this one hangs off, if any.
- `type` is the cloud's own type string, case-folded (`microsoft.keyvault/vaults`).
- `account` is the isolation boundary the resource lives in: the subscription, or the cluster.
  `group` is the container you select by: resource group, or namespace. `region` is empty for
  global resources. `tags` are a selection key and nothing else.
- `document` is the resource's full configuration exactly as the cloud returned it, minus the
  values on the redaction list. It is the source material for every derivation the console makes.
- `redactions[]` lists each value removed from `document` before it left your cloud, as a
  dotted `path` and a `reason`. The key survives with `[REDACTED]` in place of the value. The rules
  are in [redaction.md](redaction.md).

### `dependencies[]`

One entry per pointer the collector found from one resource to another: resource `from` names
`to` at property path `via` in `from`'s document. A dependency records only that a pointer
exists. It is an observation, not a claim that the target is required; whether it is fatal or
optional is a judgment the console makes, because the same pointer can be optional in general
and mandatory under a compliance mandate.

`resolution` says whether the target was actually scanned, stated relative to this scan:

| `resolution` | Meaning |
|---|---|
| `in-scan` | the target is a resource in this estate |
| `child-of-scanned` | the target hangs off a resource in this estate (a subnet, an IP configuration, a private-endpoint connection); `resolvedTo` names that ancestor |
| `out-of-scan` | neither: cross-account, cross-tenant, global, or deleted |

Only a collector can produce these, because recognizing that a string is an ARM resource id is
cloud-specific parsing, and cloud-specific parsing stops at this boundary. Past it, `id` and
`type` are opaque keys: compared, indexed, looked up, never parsed.

## Where it goes

By default, nowhere. `scanner scan` prints the estate to stdout and exits. The install template
writes it to a file share in a storage account you own. Read it before you send it anywhere.

If you set `PARITY_API_URL` (or `--api-url`), the scanner POSTs the estate to
`$PARITY_API_URL/v1/scans` with the key from `PARITY_API_KEY` in a request header. The URL must be
`https://`; `agent/internal/upload/upload.go:43-48` refuses anything else, including localhost.

## What the binary talks to

The endpoints the binary connects to during `scan`: `login.microsoftonline.com` (token),
`management.azure.com` (Resource Graph and ARM), `*.vault.azure.net` (secret names, when the
role is granted), and `PARITY_API_URL` if you set it. During `scan-cluster`: the cluster's own
API server, `login.microsoftonline.com` when the token for it comes from Entra rather than the
pod's projected service-account token, and `PARITY_API_URL` if set. Nothing else. A way to make
the binary contact a host not on this list is in scope for [SECURITY.md](../SECURITY.md).
