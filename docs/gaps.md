# Gaps

A gap is one thing the scan could not read, or read without screening. Silence is never a
verdict: a resource with no app settings and a resource whose app settings were never fetched
look identical on the wire unless the second one carries a gap. So an estate records every place
it could not look, with a reason, rather than dropping it, and an empty gap list is a claim that
the scan was complete, not a default.

Every gap carries three fields (`contract/estate.go`, type `Gap`): `reason`, one of the values
below; `target`, the resource id or a description of what went unread; and `detail`, free text
for a human. The rule from [permissions.md](permissions.md) applies: a gap should say which
permission would close it, so you can make an informed trade rather than read a bug report. A
gap that names no remedy is a defect; report it.

The reasons are few on purpose. Each has a different owner and a different fix.

| Reason | Meaning | Who fixes it |
|---|---|---|
| `not-attempted` | The collector did not fetch it. This is a bug, not a limit; on a complete scan the count should be zero | us: open an issue |
| `permission-denied` | The credential lacks the permission. The detail names the role that would close it | you, by granting a role narrower than Owner, or by deciding not to |
| `data-plane` | The value lives behind the resource's own data plane and the scanner deliberately never reads it: secret values, database logins, certificate private keys, queue contents, volume data | nobody: permanent and intentional |
| `no-collector` | It needs a collector that does not exist yet | us, when the collector ships |
| `out-of-scope` | It belongs to an account this scan was not invited into. Subscriptions are onboarded, never auto-adopted | you, by scanning that account too |
| `excluded` | The collector can read it and deliberately does not, because collecting it would be wrong rather than merely unnecessary. Kubernetes Pods and ReplicaSets are the case: a controller creates them from a spec that is collected, so restoring them would fight the controller that owns them | nobody: permanent and intentional |
| `unresolved` | A reference was read and cannot be expressed as a resource id from the plane that read it: a pod's image naming a registry by its login server, a service account's workload-identity annotation carrying a client id. The data is present; the join is the engine's to make | nobody: the console joins the two planes |
| `unscreened` | The collector shipped fields it did not check against the redaction list. The value was read and was sent. It is not a claim that a secret leaked; it is a claim that nobody has looked. See [redaction.md](redaction.md) | us, by adding the path to the list, once you tell us it is a secret to you |

Two gap-like facts live elsewhere in the estate rather than in the gap list:

- **A reference whose target was not scanned** is a dependency with `resolution: out-of-scan`.
  Every dependency says whether its target is in this estate (`in-scan`), hangs off a resource in
  it (`child-of-scanned`, with `resolvedTo` naming the ancestor), or is neither: cross-account,
  cross-tenant, global, or deleted. The distinction is stated relative to this scan, which is
  what makes it actionable: "we did not scan it" is fixable by onboarding the account; "it does
  not exist" is not.
- **A value that was removed** is a redaction on the resource, not a gap: the key survives, the
  value is `[REDACTED]`, and `resource.redactions` lists the path and the reason.

The full schema is in [estate.md](estate.md).
