# Redaction

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

The value is replaced, never the key: the key survives in the document with `[REDACTED]` in
place of the value (`contract.RedactedValue`). A deleted key would be indistinguishable from a
key that was never set, and that ambiguity is what the gap list exists to prevent.

The list is curated on purpose: nothing is redacted on suspicion, and each entry carries a
reason. `TestTranslateNeverRedactsJoinKeys` in `agent/internal/collectors/azure/` fails if a rule
ever removes a value the dependency graph joins on.

The lines that enforce all of this, with file and line, are tabulated in
[SECURITY.md](../SECURITY.md) under *The metadata-only promise, and where it is enforced*.
The permissions each collector asks for, and what is recorded when one is missing, are in
[permissions.md](permissions.md).
