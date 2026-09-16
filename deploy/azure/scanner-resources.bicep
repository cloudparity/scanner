// Everything the scanner needs inside one resource group. Deleting the group removes all of it.
// The subscription-scope Reader assignment lives in scanner.bicep, because a role assignment at
// subscription scope cannot be created from a resource-group deployment.

param location string
param image string
param registryServer string
param registryResourceId string
param targetSubscriptionId string
param storageAccountName string

// The two parameters that connect this job to the console. Both empty (the default) means the
// estate is written to the file share below and nothing leaves the subscription. Both set means
// the scanner uploads the estate to the Cloud Parity API instead and it appears in the console
// under the customer's organisation. The url without the key makes the scanner refuse at startup
// (`upload: no api key`) rather than run a scan it cannot deliver; the key without the url is the
// file-share path with a secret fetched and never read. Uploading also needs a scanner that can
// (built from main at or after 8c30031) - see the args below and deploy/azure/README.md.
@description('Where to upload the estate. Empty (default) writes it to the file share and nothing leaves the subscription.')
param parityApiUrl string = ''

@description('Key Vault secret URI holding the Cloud Parity API key, e.g. https://kv.vault.azure.net/secrets/parity-api-key. Empty when parityApiUrl is empty.')
param parityApiKeySecretUri string = ''

var estateShareName = 'estate'

// A user-assigned identity, not system-assigned. The Reader assignment in the parent template
// needs the principal id BEFORE the job exists, and a system-assigned identity only comes into
// being with its resource — which would force a two-phase deployment.
resource identity 'Microsoft.ManagedIdentity/userAssignedIdentities@2023-01-31' = {
  name: 'cloud-parity-scanner-identity'
  location: location
}

// The estate lands here, in the CUSTOMER's storage account, unless parityApiUrl is set. Nothing
// leaves the subscription unless they choose to send it, which is the whole point of writing it
// to a share by default rather than posting it somewhere. The share is created either way, so a
// customer can switch between the two by redeploying with different parameters and nothing else
// changes.
resource storage 'Microsoft.Storage/storageAccounts@2023-05-01' = {
  name: storageAccountName
  location: location
  sku: {
    name: 'Standard_LRS'
  }
  kind: 'StorageV2'
  properties: {
    minimumTlsVersion: 'TLS1_2'
    allowBlobPublicAccess: false
    supportsHttpsTrafficOnly: true
  }
}

resource fileServices 'Microsoft.Storage/storageAccounts/fileServices@2023-05-01' = {
  parent: storage
  name: 'default'
}

resource estateShare 'Microsoft.Storage/storageAccounts/fileServices/shares@2023-05-01' = {
  parent: fileServices
  name: estateShareName
  properties: {
    shareQuota: 5
  }
}

// AcrPull, only for the mirror path. A public image needs no credential at all, which is why
// this is conditional rather than always present — and its absence was why the first deployment
// failed with "unable to pull image using Managed identity".
var acrPullRoleId = subscriptionResourceId('Microsoft.Authorization/roleDefinitions', '7f951dda-4ed3-4680-a7ca-43fe172d538d')

resource registry 'Microsoft.ContainerRegistry/registries@2023-07-01' existing = if (!empty(registryResourceId)) {
  name: last(split(registryResourceId, '/'))
}

resource acrPull 'Microsoft.Authorization/roleAssignments@2022-04-01' = if (!empty(registryResourceId)) {
  scope: registry
  name: guid(registryResourceId, identity.id, 'AcrPull')
  properties: {
    roleDefinitionId: acrPullRoleId
    principalId: identity.properties.principalId
    principalType: 'ServicePrincipal'
    description: 'Cloud Parity scanner: pull the mirrored scanner image.'
  }
}

// No Log Analytics workspace. The scanner's OUTPUT is the estate file, and that lands on the
// mounted share regardless, so a workspace bought diagnostics rather than the deliverable - and
// it cost a resource, a listKeys() call, and the only shared key this template ever handled.
//
// The trade this makes, stated plainly: with destination 'none' the job's stdout and stderr are
// retained NOWHERE. Execution status still comes from `az containerapp job execution list`, so a
// failure is visible, but WHY it failed is not. If a customer scan fails and needs diagnosing,
// point the environment at their existing workspace rather than reintroducing one here.
resource environment 'Microsoft.App/managedEnvironments@2024-03-01' = {
  name: 'cloud-parity-scanner-environment'
  location: location
  // appLogsConfiguration is OMITTED, not set to 'none'.
  //
  // Setting destination: 'none' fails preflight with "App Logs destination 'none' not supported.
  // Supported values: 'log-analytics', 'azure-monitor' or none" - a message that contradicts
  // itself, and whose actual meaning is that the ABSENCE of the block is how you say none. The
  // literal string is rejected.
  //
  // That mistake survived because this version of the template was never once deployed
  // successfully, and because `az deployment sub create` in azure-cli 2.73.0 cannot report a
  // template validation error at all: its own error formatter reads the HTTP response body a
  // second time and dies with "The content for this response was already consumed", swallowing
  // Azure's message. The error above was only recoverable by PUTting the deployment through
  // `az rest` and then reading `az deployment operation sub list`.
  properties: {}
}

// The share is registered on the environment so the job can mount it.
resource environmentStorage 'Microsoft.App/managedEnvironments/storages@2024-03-01' = {
  parent: environment
  name: 'estate'
  properties: {
    azureFile: {
      accountName: storage.name
      accountKey: storage.listKeys().keys[0].value
      shareName: estateShareName
      accessMode: 'ReadWrite'
    }
  }
  dependsOn: [
    estateShare
  ]
}

// A JOB, not an app. The scanner runs once and exits, so there is nothing to keep alive: no
// ingress, no inbound networking, no replica sitting idle. Manual trigger here so a customer
// runs it deliberately the first time; switch triggerType to 'Schedule' with a cron expression
// for continuous scanning.
resource job 'Microsoft.App/jobs@2024-03-01' = {
  name: 'cloud-parity-scanner'
  location: location
  identity: {
    type: 'UserAssigned'
    userAssignedIdentities: {
      '${identity.id}': {}
    }
  }
  dependsOn: empty(registryResourceId) ? [] : [
    acrPull
  ]
  properties: {
    environmentId: environment.id
    configuration: {
      triggerType: 'Manual'
      // 3 hours, not 30 minutes. A scan of this testbed takes ~40 seconds, but diagnosticSettings
      // costs one ARM call per resource, so a large estate is hundreds to thousands of calls at
      // fetchConcurrency in flight - and a job killed at the timeout yields a PARTIAL estate, which
      // is the one outcome worse than a slow one. Raised before it is needed rather than during an
      // incident. A job that exits in 40s is not billed for the headroom.
      replicaTimeout: 10800
      replicaRetryLimit: 1
      manualTriggerConfig: {
        parallelism: 1
        replicaCompletionCount: 1
      }
      registries: empty(registryServer) ? [] : [
        {
          server: registryServer
          identity: identity.id
        }
      ]
      // The API key is never a parameter of this template: a parameter value lands in the
      // deployment history, readable by anyone with Reader on the subscription. The customer
      // puts the key in THEIR Key Vault and passes the secret's URI; Container Apps reads it with
      // the job's identity and hands it to the container as an environment variable, so the
      // value is visible only inside the running container.
      //
      // The identity must hold `Key Vault Secrets User` on that secret. That is a grant the
      // customer makes, not this template: the vault is theirs and is not in this resource
      // group, and a subscription-wide grant would let the scanner read every secret they have.
      // Container Apps checks the reference when the job is created, so the grant has to exist
      // before the deployment that sets parityApiKeySecretUri - deploy/azure/README.md has the order.
      secrets: empty(parityApiKeySecretUri) ? [] : [
        {
          name: 'parity-api-key'
          keyVaultUrl: parityApiKeySecretUri
          identity: identity.id
        }
      ]
    }
    template: {
      containers: [
        {
          name: 'scanner'
          image: image
          resources: {
            cpu: json('0.5')
            memory: '1Gi'
          }
          // Without an API url the scanner writes the estate to stdout. A Container App Job's
          // stdout only reaches Log Analytics, where a large JSON document arrives split across
          // rows, so it is redirected onto the mounted share instead. With an API url the
          // scanner uploads the estate itself and prints only the result, so nothing is
          // redirected - the estate goes to the console, not the share.
          command: [
            '/bin/sh'
            '-c'
          ]
          // --exclude-groups is the scanner's OWN resource group. A scan that reports the
          // scanner is measuring itself: the job, identity, environment and storage account
          // here exist only to look at the estate, are not part of any application, and
          // a fresh install recreates them - so no recovery plan should ever see them. The
          // scanner cannot infer its own group from inside the container, so it is passed in.
          //
          // The key is deliberately absent from this line: it reaches the scanner through the
          // PARITY_API_KEY environment variable, never a --api-key flag, because the command is
          // visible in the job definition and in every execution's history.
          //
          // The upload command asks the binary before it scans. A scanner built before main
          // commit 8c30031 (2026-08-16) has no -api-url flag and reads neither variable: given
          // PARITY_API_URL it prints the estate to a stdout this job keeps nowhere, exits 0, and
          // the customer sees a successful execution and an empty console. scanner.bicep refuses
          // that combination for the DEFAULT image, but a customer who mirrored an old tag into
          // their own registry passes a different image string and gets past it - so the probe
          // is here, on the binary that actually runs, and the execution fails instead. The
          // file-share command needs no probe; every scanner ever published can print.
          args: empty(parityApiUrl) ? [
            'scanner scan --subscription "$TARGET_SUBSCRIPTION" --exclude-groups "$OWN_RESOURCE_GROUP" > /estate/estate.json && wc -c /estate/estate.json'
          ] : [
            'scanner scan -h 2>&1 | grep -q -- -api-url || { echo "this scanner image cannot upload: it was built before main commit 8c30031 and ignores PARITY_API_URL. Use an image built at or after it." >&2; exit 1; }; scanner scan --subscription "$TARGET_SUBSCRIPTION" --exclude-groups "$OWN_RESOURCE_GROUP"'
          ]
          env: concat([
            {
              name: 'TARGET_SUBSCRIPTION'
              value: targetSubscriptionId
            }
            {
              // DefaultAzureCredential tries EnvironmentCredential, then workload identity, then
              // managed identity. Naming the client id is what makes it pick THIS user-assigned
              // identity rather than guessing when several are attached.
              name: 'AZURE_CLIENT_ID'
              value: identity.properties.clientId
            }
            {
              name: 'OWN_RESOURCE_GROUP'
              value: resourceGroup().name
            }
          ], empty(parityApiUrl) ? [] : [
            {
              // The scanner reads both from the environment (agent/cmd/scanner/main.go, apiFlags).
              // An empty url means "print the estate", so the variable is only set when there
              // is somewhere to send it.
              name: 'PARITY_API_URL'
              value: parityApiUrl
            }
          ], empty(parityApiKeySecretUri) ? [] : [
            {
              name: 'PARITY_API_KEY'
              secretRef: 'parity-api-key'
            }
          ])
          volumeMounts: [
            {
              volumeName: 'estate'
              mountPath: '/estate'
            }
          ]
        }
      ]
      volumes: [
        {
          name: 'estate'
          storageType: 'AzureFile'
          storageName: environmentStorage.name
        }
      ]
    }
  }
}

output jobName string = job.name
output identityPrincipalId string = identity.properties.principalId
output identityClientId string = identity.properties.clientId
output estateShare string = estateShareName
// Where the estate goes, so a customer reading the deployment output can tell which path they
// deployed without decoding the job definition.
output estateDestination string = empty(parityApiUrl) ? 'file share ${estateShareName}' : parityApiUrl
