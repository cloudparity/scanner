# Permissions

What the scanner asks for, what each grant unlocks, and what the estate records when a grant is
absent. This is the one place the ask is written down; the install template, the Kubernetes
manifest and the README point here rather than restating it.

## Azure: `scanner scan`

| Grant | Scope | Required or optional | What it unlocks | What is recorded if absent |
|---|---|---|---|---|
| **Reader** (`acdd72a7-3385-48ef-bd42-f606fba81ae7`) | subscription | **required** | Resource Graph, ARM control-plane GETs for child resources (private endpoint DNS zone groups, blob/file/queue/table services, containers, shares, diagnostic settings), role assignments, App Service Key Vault references | the scan fails at discovery |
| **Key Vault Reader** (`21090545-7ca7-4776-b22c-e363652d74d2`) | each vault | optional | secret **names** and metadata (`GET {vault}/secrets`). The role has `readMetadata` and not `getSecret`; the list call has no value field. A recovered vault is otherwise an empty shell | one gap per vault, reason `permission-denied`, naming this role. The collector attempts every vault; a vault reachable only over a private endpoint records a gap that says granting a role changes nothing |
| App Configuration Data Reader (`516239f1-63e1-4d78-a4de-a74fb236a071`) | each store | not requested today | key-values, including `@Microsoft.KeyVault(...)` pointers | nothing: no collector reads it yet |
| Website Contributor | each site | not requested | App Service and Function App setting **values**. `Microsoft.Web/sites/config/list/action` is an action, so no read-only role can reach it | the values are masked by Azure in what Reader returns, and the setting **names** plus which Key Vault secret each points at come from `config/configreferences/appsettings`, which Reader can read (`agent/internal/collectors/azure/appsettings.go`) |
| Reader at management-group scope | management group | not requested | policy and RBAC inherited from above the subscription | nothing: subscription Reader cannot see upward |

`deploy/azure/scanner.bicep` makes the Reader assignment and nothing else. Key Vault Reader is
not in the template: it is a data-plane role and has to be assigned per vault, so it is a
decision you make vault by vault. Note that Owner does not include it: data-plane permissions
are `DataActions`, and Owner grants `*` on `Actions` only.

Measured, on a live scan of one of our own subscriptions with the job identity holding Reader
only: 69 resources, 140 references, zero `permission-denied` gaps for the control plane (56
resources from Resource Graph and 13 from ARM GETs). A separate run with a Reader-only service
principal produced the same estate as subscription Owner.

## Kubernetes: `scanner scan-cluster`

One `ClusterRole` with one verb, `list`, on the kinds the collector reads. The file is
[`deploy/kubernetes/reader.yaml`](../deploy/kubernetes/reader.yaml); `TestReaderManifestCoversEveryKind`
in `agent/internal/collectors/k8s/kinds_test.go` fails if a kind is added to the code without
being added to the manifest.

| Grant | Scope | Required or optional | What it unlocks | What is recorded if absent |
|---|---|---|---|---|
| `list` on the kinds in `reader.yaml` | cluster | **required** | the application plane: workloads, config, networking, storage classes, RBAC | a gap per kind, reason `permission-denied` |
| `list` on `secrets` | cluster | **required**, and deliberately so | Secret **names and keys**, which a restore needs to know what each pod expects. Kubernetes has no permission that returns a name without its value, so the value arrives and is stripped in code (`agent/internal/collectors/k8s/translate.go:274`), and each removal is recorded in the resource's `redactions` | gaps on every kind that references a Secret |

Not granted: `get`, `watch`, any write verb, `exec`, `proxy`, `portforward`, `impersonate`, and
`pods`/`replicasets` (controller output; restoring them fights the controller that owns them).

## What we will not ask for

**`Directory.Read.All` (Microsoft Graph).** A role assignment's `principalId` is a bare GUID and
Graph would resolve it. It is a tenant-wide directory read requiring admin consent, a separate
approval path from ARM RBAC, and it would enrich one field. The assignment is reported as
observed, scope, role definition and principal GUID, and marked unresolved. A principal from the
source tenant is meaningless in a recovery tenant anyway; the recreated assignment targets a
principal you supply.

**`Storage Blob Data Reader` and Data Contributor.** Reading blob contents would put the scanner
in scope for your data classification (GDPR, HIPAA, PCI), turn every crash dump into a data
disclosure, and make scan cost scale with data volume instead of resource count. Azure already
replicates data (GRS, GZRS, object replication across subscriptions). Everything needed to judge
whether that is configured is on the management plane, which Reader reaches: replication SKU,
object replication policies, versioning, soft delete, point-in-time restore, immutability,
lifecycle rules, backup vault coverage. The scanner reports "this account is `Standard_LRS` with
no object replication policy" with no data access at all.

## The rule

Every gap in an estate says which permission would close it, so you can make an informed trade
rather than read a bug report. A gap that names no remedy is a defect; report it.

## `scanner backup` and `scanner prune`

These are a separate pipeline with a separate ask, and nothing in `scan` needs any of it:

- a PostgreSQL role with `REPLICATION` on the server being backed up; the scanner creates one
  logical replication slot with it and drops the slot on exit
- write access to one blob container you name (`PUT`, and `DELETE` for `prune --apply`)
- the Azure Backup permissions to trigger an on-demand backup and a restore-as-files on one
  backup instance you name

The flags and environment variables that carry these are listed at the top of
`agent/cmd/scanner/backup.go` and `agent/cmd/scanner/prune.go`. If you do not set them, these
subcommands refuse to start.
