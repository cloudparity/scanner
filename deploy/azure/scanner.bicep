// Cloud Parity scanner — the template a customer deploys into their own subscription.
//
// Deployed at SUBSCRIPTION scope, because the one permission the scanner needs is a Reader
// role assignment at subscription scope and that cannot be created from inside a resource
// group. Everything else lives in one resource group the customer can delete in one action.
//
// What the customer is agreeing to, in full:
//
//   • ONE role assignment: Reader, subscription scope. Nothing else. Measured, not assumed —
//     a service principal holding only Reader produced a byte-identical estate to subscription
//     Owner: same resources, same references, zero permission-denied gaps.
//   • A job that RUNS AND EXITS. Not a service, not a listener, no inbound networking, no
//     public ingress. It scales to zero between runs and costs approximately nothing.
//   • The estate is written to a file share in THEIR storage account. Nothing leaves the
//     subscription unless they choose to send it - which they do by setting parityApiUrl, and
//     then the estate is uploaded to the Cloud Parity console instead, authenticated with an
//     API key the customer minted in the console and keeps in their own Key Vault. That path
//     needs an image built from main at or after commit 8c30031 (2026-08-16), when the scanner
//     learned to upload; until the default image is one, the template refuses parityApiUrl
//     with the default image (see defaultImageUploads below).
//
// Deliberately NOT here, and each absence is a decision:
//   • No write permission anywhere. AD-013: subscriptions are onboarded, never auto-adopted.
//   • No data-plane roles. Key Vault Reader, App Configuration Data Reader and Storage Blob
//     Data Reader are all unnecessary today, because no code reads a data plane. They belong
//     in this template only when a collector needs them, and Storage Blob Data Reader never
//     belongs here at all — it reads blob CONTENTS, which the product deliberately does not want.
//   • No VNet injection. Every call the scanner makes today (Resource Graph, and ARM control
//     plane GETs) works from the public internet. It becomes necessary the moment the scanner
//     reads Key Vault secret names or AKS internals behind a private endpoint.

targetScope = 'subscription'

@description('Resource group to create for the scanner. Deleting it removes everything except the role assignment.')
param resourceGroupName string = 'cloud-parity-scanner-rg'

@description('Region for the scanner job. Independent of where the scanned resources live — Resource Graph is global.')
param location string = 'eastus'

// HOW THE IMAGE GETS HERE, because this is the part that surprises people:
//
// The customer never builds it. We publish one image per release to a PUBLIC registry, exactly
// like a binary release, and this template pulls it anonymously — no registry to create, no
// Dockerfile, no build step, no credentials, no AcrPull grant.
//
// The only reason registryServer/registryResourceId exist is the enterprise that forbids
// pulling from an external registry. That customer MIRRORS the published image into their own
// registry with one command and no Docker:
//
//   az acr import --name <theirRegistry> \
//     --source ghcr.io/cloudparity/scanner:latest --image parity-scanner:v7
//
// then passes both parameters, and the template grants the job's identity AcrPull on that
// registry. Still a mirror, never a build.
//
// TODO: this namespace is a personal GHCR account and must move to a shared organisation before
// any customer deploys it. A default pointing at one founder's personal account is a bus factor
// of one: it disappears if that account does, and neither founder can publish a release without
// the other. Deliberately left as a real, pullable image rather than an aspirational one, so the
// template's default works today instead of failing with a 404.
@description('Container image holding the scanner binary. Defaults to the published public image.')
param image string = 'ghcr.io/cloudparity/scanner:latest'

// The same tag again, as a var, because Bicep does not let a parameter default reference a var
// and the guard below has to know what "the default image" is. template_test.go holds the two
// equal; bump both together.
var defaultImage = 'ghcr.io/cloudparity/scanner:latest'

// Whether the default image can upload. Every tag published so far - v1 to v8 - was built
// before the upload code landed on main (8c30031, 2026-08-16). Those binaries read neither
// PARITY_API_URL nor PARITY_API_KEY: given both, the job prints the estate to a stdout nobody
// keeps, exits 0 and delivers nothing, and the customer sees a successful execution and an
// empty console. So while this is false the template refuses parityApiUrl with the default
// image (below) rather than deploying that job.
//
// To lift it: publish an image from main at or after 8c30031, point defaultImage and the
// parameter default at it, and set this to true. verify.yml pulls the pinned image, runs
// `scan -h` and fails the build if this flag disagrees with the binary in either direction, so
// the flag cannot drift from what the tag actually contains.
var defaultImageUploads = false

@description('Only for customers mirroring the image into their own private registry. Leave empty to pull the public image anonymously.')
param registryServer string = ''

@description('Resource id of the private registry, when registryServer is set. The job identity is granted AcrPull on it.')
param registryResourceId string = ''

@description('Subscription the scanner reads. Defaults to the one this template is deployed into.')
param targetSubscriptionId string = subscription().subscriptionId

@description('Globally unique name for the storage account that receives the estate JSON.')
param storageAccountName string

// Upload to the console, or not. Both empty is the default and the estate stays on the file
// share. To send it to the console, mint a key under Settings > Keys, put it in a Key Vault
// secret (from a file, never a flag - `az keyvault secret set --file`), grant the scanner's
// identity `Key Vault Secrets User` on that one secret, and pass both - with an image that can
// upload (deploy/azure/README.md, path 2). The key itself is never a parameter: parameter
// values are kept in the deployment history.
@description('Where to upload the estate. Empty (default) writes it to the file share and nothing leaves the subscription.')
param parityApiUrl string = ''

@description('Key Vault secret URI holding the Cloud Parity API key, e.g. https://kv.vault.azure.net/secrets/parity-api-key. Empty when parityApiUrl is empty.')
param parityApiKeySecretUri string = ''

// Reader. The built-in definition id is stable across every Azure tenant.
var readerRoleId = subscriptionResourceId('Microsoft.Authorization/roleDefinitions', 'acdd72a7-3385-48ef-bd42-f606fba81ae7')

resource scannerGroup 'Microsoft.Resources/resourceGroups@2024-03-01' = {
  name: resourceGroupName
  location: location
  tags: {
    'cloud-parity': 'scanner'
  }
}

// The refusal. fail() aborts the deployment with this message when it is evaluated, and it is
// evaluated only in that one case: an upload requested from the default image while the default
// image cannot upload. ARM evaluates it at validation, before the resource group or anything
// else is created (`az deployment sub validate` returns InvalidTemplate with the message). A
// mirrored image passes here with a different string, so the job's own command probes the
// binary too (scanner-resources.bicep).
var guardedImage = !empty(parityApiUrl) && image == defaultImage && !defaultImageUploads
  ? fail('parityApiUrl is set, but the default image ${defaultImage} was built before the scanner could upload (main commit 8c30031, 2026-08-16): it would ignore PARITY_API_URL, print the estate to a stdout nobody keeps and exit 0. Pass image=<a tag built from main at or after 8c30031>, or leave parityApiUrl empty to write the estate to the file share')
  : image

module scanner 'scanner-resources.bicep' = {
  name: 'cloud-parity-scanner'
  scope: scannerGroup
  params: {
    location: location
    image: guardedImage
    registryServer: registryServer
    registryResourceId: registryResourceId
    targetSubscriptionId: targetSubscriptionId
    storageAccountName: storageAccountName
    parityApiUrl: parityApiUrl
    parityApiKeySecretUri: parityApiKeySecretUri
  }
}

// The single grant. Scoped to the subscription because the scanner's job is to see the whole
// estate: a resource-group-scoped Reader would produce a silently partial scan, and Resource
// Graph filters without saying so — it returns 200 with only the rows the principal can read,
// and TotalRecords counts only those, so no internal check can detect it.
resource readerAssignment 'Microsoft.Authorization/roleAssignments@2022-04-01' = {
  // Derived from values known at the START of the deployment, not from the module's output.
  // Bicep requires a role assignment's name to be computable before anything runs, and it only
  // has to be a stable unique GUID — it does not have to encode the principal.
  name: guid(subscription().id, resourceGroupName, 'cloud-parity-scanner-reader')
  properties: {
    roleDefinitionId: readerRoleId
    principalId: scanner.outputs.identityPrincipalId
    principalType: 'ServicePrincipal'
    description: 'Cloud Parity scanner: read-only discovery of the estate. No write permission is granted anywhere.'
  }
}

output jobName string = scanner.outputs.jobName
output identityPrincipalId string = scanner.outputs.identityPrincipalId
output estateShare string = scanner.outputs.estateShare
output storageAccount string = storageAccountName
output estateDestination string = scanner.outputs.estateDestination
