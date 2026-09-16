# Deploying the scanner inside your own subscription

`scanner.bicep` is the template a customer deploys. It creates one resource group holding a
Container Apps **job** that runs the published scanner image once per trigger, a user-assigned
identity for it, and a storage account with a file share — and makes exactly one grant outside
that group: **Reader** on the subscription, to that identity. The header comment of
`scanner.bicep` is the full list of what you are agreeing to; this file is how to run it.

Two places the estate can go. The template does the first by default.

| | Estate lands in | Leaves the subscription | Parameters |
|---|---|---|---|
| **File share** (default) | `estate.json` on the `estate` share of the storage account you name | nothing | none beyond `storageAccountName` |
| **Console** | your organisation in the Cloud Parity console | resource metadata only, over HTTPS, authenticated with a key you minted | `parityApiUrl` and `parityApiKeySecretUri`, and an `image` that can upload (see path 2) |

Both paths use the same identity and the same single Reader grant. The share is created either
way, so switching between them is a redeploy with different parameters and nothing else changes.

## Prerequisites

- `az` logged in as a principal that can create a resource group and a subscription-scope role
  assignment (Owner, or User Access Administrator plus Contributor).
- `az bicep install` once, so `az deployment` can compile the template.

## Path 1 — the estate on your own file share

```sh
az deployment sub create --location eastus --template-file scanner.bicep \
  --parameters storageAccountName=<globally unique, 3-24 lowercase letters and digits>
az containerapp job start --name cloud-parity-scanner --resource-group cloud-parity-scanner-rg
```

The job exits when the scan is done — tens of seconds for a small subscription, minutes for a
large one. `az containerapp job execution list --name cloud-parity-scanner --resource-group
cloud-parity-scanner-rg` shows whether it succeeded; the estate is `estate.json` on the `estate`
share. Read it before sending it anywhere; that is why this is the default.

Optional parameters: `targetSubscriptionId` (scan a different subscription than the one you deploy
into — the Reader grant still lands on the deployment subscription, so grant it on the target
yourself), `location`, `resourceGroupName`, and `image` / `registryServer` / `registryResourceId`
for the enterprise that mirrors the image into a private registry (see the comment above `image`
in `scanner.bicep`).

## Path 2 — the estate in the console

**Minimum image: a tag built from `main` at or after commit `8c30031` (2026-08-16), the commit
that taught the scanner to upload.** A scanner built before it has no `-api-url` flag and reads
neither `PARITY_API_URL` nor `PARITY_API_KEY`; given both, it prints the estate to a stdout this
job keeps nowhere, exits 0, and you see a successful execution and an empty console. As of this
writing **no published tag qualifies** — `v8`, the newest, was built 2026-08-14 — so the template's
default image cannot take this path yet, and two things stop you from finding that out the slow
way:

- with the default image, the deployment is **refused at validation** (`fail(...)` in
  `scanner.bicep`, keyed on `var defaultImageUploads`) before anything is created, and the message
  says why. Pass `image=<a qualifying tag>` to go ahead. When a qualifying tag is published and
  pinned as the default, that variable flips to `true` and the refusal goes away — CI checks the
  variable against the pinned image on every pull request, so it cannot claim more than the
  binary does.
- with any image — the default or one you mirrored — the job's command asks the binary for
  `-api-url` before it scans and **exits 1** if the flag is missing. An execution that shows as
  failed within seconds of starting on this path is that check; `az containerapp job execution
  list` shows the status, and the reason is on the container's stderr if you pointed the
  environment at a Log Analytics workspace.

The scanner uploads with an API key. The key is **never a template parameter**: parameter values
are stored in the deployment history, readable by anyone with Reader on the subscription — the
same role the scanner holds. Instead the key lives in a Key Vault you own, and the job's identity
reads that one secret at start.

**1. Mint a key** in the console under *Settings › Keys*. It is shown once. Put it in a file, not
a shell variable and not a flag:

```sh
umask 077 && cat > parity-api-key.txt    # paste the key, then ctrl-d
```

**2. Store it in a Key Vault you own.** Any RBAC-enabled vault works; the scanner never sees the
vault, only this one secret.

```sh
az keyvault secret set --vault-name <your-vault> --name parity-api-key --file parity-api-key.txt
rm parity-api-key.txt
```

**3. Deploy once without the console parameters**, exactly as in path 1. This creates the job's
identity, whose principal id the deployment prints as `identityPrincipalId`. (Container Apps
resolves a Key Vault reference when the job is created, so the grant in the next step has to
exist *before* the deployment that carries the parameters — and the identity has to exist before
you can grant it anything.)

**4. Grant the identity `Key Vault Secrets User` on that one secret** — not on the vault, so the
scanner can read nothing else you keep there:

```sh
az role assignment create --role "Key Vault Secrets User" \
  --assignee-object-id <identityPrincipalId from step 3> --assignee-principal-type ServicePrincipal \
  --scope "$(az keyvault show --name <your-vault> --query id -o tsv)/secrets/parity-api-key"
```

**5. Redeploy with both parameters.** Same command as step 3 plus the two below; everything already
deployed is left as it is and only the job definition changes.

```sh
az deployment sub create --location eastus --template-file scanner.bicep \
  --parameters storageAccountName=<same as step 3> \
               parityApiUrl=https://api.cloudparity.net \
               parityApiKeySecretUri=https://<your-vault>.vault.azure.net/secrets/parity-api-key
az containerapp job start --name cloud-parity-scanner --resource-group cloud-parity-scanner-rg
```

The deployment prints `estateDestination` so you can see which path is live. The estate appears
under *Scans* in the console when the execution finishes; nothing is written to the file share on
this path.

What the job does with the two parameters, so you can check it against the template:

- `configuration.secrets` gains one entry, `parity-api-key`, that points at your secret URI and is
  read with the job's user-assigned identity.
- the container gets `PARITY_API_URL` from `parityApiUrl` and `PARITY_API_KEY` from that secret
  reference — as environment variables, which is how the scanner reads them. The key is never on
  the command line, because the command is visible in the job definition and in every execution.
- the command drops the `> /estate/estate.json` redirect: the scanner uploads the estate itself.

`parityApiUrl` without `parityApiKeySecretUri` makes the scanner refuse at startup (`upload: no
api key`) rather than scan an estate it cannot deliver. The other way round — a secret URI with no
`parityApiUrl` — is just path 1: the key is fetched into the container and never read. Set both
or neither.

**Rotating or revoking the key.** Revoke it in *Settings › Keys*; the next execution fails to
upload. To rotate, mint a new key, `az keyvault secret set` it under the same name, and the job
picks up the new version at its next start — the secret URI has no version, so it always resolves
to the latest.

## What the template never does

No write permission anywhere, no data-plane roles, no VNet injection, no Log Analytics workspace
(the job's stdout is retained nowhere — `az containerapp job execution list` says whether a run
succeeded, not why it failed; point the environment at your own workspace if you need that). Each
absence is explained where it would otherwise appear in `scanner.bicep` and
`scanner-resources.bicep`.

## Checking the template

`az bicep build --file scanner.bicep` compiles it. `go test ./deploy/azure/` from the repo root
compiles both files and checks the job declares the parameters and environment above, that the
upload command probes the binary first, and that the subscription template refuses `parityApiUrl`
with a default image that cannot upload (it skips when no Bicep compiler is installed). CI does
both on every pull request and additionally checks that the default image tag exists, is
anonymously pullable, and can or cannot upload exactly as `var defaultImageUploads` in
`scanner.bicep` says — by pulling it and running `scan -h`.
