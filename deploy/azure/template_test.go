// Compiles the customer-facing Bicep templates and checks the shape of what they produce.
//
// Not a deployment. Bicep compiles to an ARM template whose conditional parts are expression
// strings, so the checks here are on what the job DECLARES: which parameters exist, which
// environment variables the container gets and where each one comes from. That is the part the
// scanner binary depends on (it reads PARITY_API_URL and PARITY_API_KEY from the environment), and
// the part that shipped wrong once: a template that wrote the estate to a file share and never
// told the scanner where the API was, so a customer who deployed it could not see their estate.
//
// Needs a Bicep compiler - `bicep` on PATH, or `az` with the bicep extension - and skips without
// one, because `go test ./...` runs on machines with neither. CI's install-template job installs
// `bicep` and runs this package, so the skip is a local convenience, not a gap in the gate.
package azure

import (
	"bytes"
	"encoding/json"
	"os/exec"
	"strings"
	"testing"
)

// compile returns the ARM template for one Bicep file, decoded.
func compile(t *testing.T, file string) map[string]any {
	t.Helper()
	var cmd *exec.Cmd
	switch {
	case exec.Command("bicep", "--version").Run() == nil:
		cmd = exec.Command("bicep", "build", file, "--stdout")
	case exec.Command("az", "bicep", "version").Run() == nil:
		cmd = exec.Command("az", "bicep", "build", "--file", file, "--stdout")
	default:
		t.Skip("no bicep compiler on PATH (bicep, or az with the bicep extension)")
	}
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	out, err := cmd.Output()
	if err != nil {
		t.Fatalf("compile %s: %v\n%s", file, err, stderr.String())
	}
	var arm map[string]any
	if err := json.Unmarshal(out, &arm); err != nil {
		t.Fatalf("compile %s: not JSON: %v", file, err)
	}
	return arm
}

// resource finds the one resource of a type in a compiled template, as JSON text. Text, because
// the interesting parts are ARM expressions - conditional arrays compile to a single string - and
// the checks below are "does this declaration mention X", which holds whichever form Bicep chose.
func resource(t *testing.T, arm map[string]any, typ string) string {
	t.Helper()
	for _, r := range arm["resources"].([]any) {
		res := r.(map[string]any)
		if res["type"] == typ {
			// Not json.Marshal: it escapes > and & for HTML, and the job command has both.
			var b bytes.Buffer
			enc := json.NewEncoder(&b)
			enc.SetEscapeHTML(false)
			if err := enc.Encode(res); err != nil {
				t.Fatal(err)
			}
			return b.String()
		}
	}
	t.Fatalf("no %s resource in the compiled template", typ)
	return ""
}

// param returns a parameter's declaration, or fails if the template has no such parameter.
func param(t *testing.T, arm map[string]any, name string) map[string]any {
	t.Helper()
	p, ok := arm["parameters"].(map[string]any)[name].(map[string]any)
	if !ok {
		t.Fatalf("parameter %q is not declared", name)
	}
	return p
}

// The two parameters that turn the file-share job into one that uploads to the console. Both
// default to empty so an existing deployment keeps writing to the share, and both exist on the
// subscription-scope template a customer actually deploys, not only on the module.
func TestUploadParametersDefaultToOff(t *testing.T) {
	for _, file := range []string{"scanner.bicep", "scanner-resources.bicep"} {
		arm := compile(t, file)
		for _, name := range []string{"parityApiUrl", "parityApiKeySecretUri"} {
			p := param(t, arm, name)
			if p["type"] != "string" {
				t.Errorf("%s: %s type = %v, want string", file, name, p["type"])
			}
			if v, ok := p["defaultValue"]; !ok || v != "" {
				t.Errorf("%s: %s default = %#v, want the empty string", file, name, v)
			}
		}
	}
}

// scanner.bicep threads both parameters into the module rather than hardcoding them.
func TestSubscriptionTemplateThreadsUploadParameters(t *testing.T) {
	arm := compile(t, "scanner.bicep")
	mod := resource(t, arm, "Microsoft.Resources/deployments")
	for _, name := range []string{"parityApiUrl", "parityApiKeySecretUri"} {
		if !strings.Contains(mod, "[parameters('"+name+"')]") {
			t.Errorf("the module is not passed parameters('%s')", name)
		}
	}
}

// The job's environment is what the scanner reads (agent/cmd/scanner/main.go, apiFlags): the url
// as a plain value, the key ONLY through a secret reference that Container Apps resolves from the
// customer's Key Vault. The key never appears as a literal, a parameter value, or on the command
// line - a flag lands in the process list and in the job's execution history.
func TestJobReceivesApiUrlAndKeyFromEnvironment(t *testing.T) {
	arm := compile(t, "scanner-resources.bicep")
	job := resource(t, arm, "Microsoft.App/jobs")

	must := map[string]string{
		"the url env var":                `'name', 'PARITY_API_URL', 'value', parameters('parityApiUrl')`,
		"the key env var by secretRef":   `'name', 'PARITY_API_KEY', 'secretRef', 'parity-api-key'`,
		"the secret from the vault":      `'name', 'parity-api-key', 'keyVaultUrl', parameters('parityApiKeySecretUri')`,
		"resolved by the job's identity": `'identity', resourceId('Microsoft.ManagedIdentity/userAssignedIdentities', 'cloud-parity-scanner-identity')`,
	}
	for what, want := range must {
		if !strings.Contains(job, want) {
			t.Errorf("job does not declare %s: missing %q", what, want)
		}
	}
	mustNot := map[string]string{
		"the key as a plain env value": `'PARITY_API_KEY', 'value'`,
		"the key on the command line":  `--api-key`,
		"the key env on the cmd line":  `$PARITY_API_KEY`,
	}
	for what, bad := range mustNot {
		if strings.Contains(job, bad) {
			t.Errorf("job exposes %s: found %q", what, bad)
		}
	}
}

// With no API url the job keeps doing what it always did - write the estate onto the mounted
// share - and with one it uploads instead of redirecting stdout. Both commands exist, chosen by
// the parameter, and both still pass the flags verify.yml checks for.
func TestJobCommandSwitchesOnApiUrl(t *testing.T) {
	arm := compile(t, "scanner-resources.bicep")
	job := resource(t, arm, "Microsoft.App/jobs")

	share := `scanner scan --subscription \"$TARGET_SUBSCRIPTION\" --exclude-groups \"$OWN_RESOURCE_GROUP\" > /estate/estate.json && wc -c /estate/estate.json`
	upload := `scanner scan --subscription \"$TARGET_SUBSCRIPTION\" --exclude-groups \"$OWN_RESOURCE_GROUP\"'`
	for what, want := range map[string]string{
		"the file-share command":     share,
		"the upload command":         upload,
		"the switch on parityApiUrl": `[if(empty(parameters('parityApiUrl')), createArray('scanner scan`,
	} {
		if !strings.Contains(job, want) {
			t.Errorf("job args do not contain %s: missing %q", what, want)
		}
	}
}

// The default image is a hard dependency on a scanner build, and every tag published so far was
// built before the upload code landed on main (8c30031, 2026-08-16). Given PARITY_API_URL, such a
// binary ignores it, prints the estate to a stdout nobody keeps and exits 0 - the customer sees a
// successful execution and an empty console. So until defaultImageUploads says the pinned tag can
// upload, scanner.bicep refuses parityApiUrl with the default image at deployment time instead of
// deploying that job. verify.yml runs the pinned image and checks the flag agrees with the binary.
func TestDefaultImageRefusesUploadUntilItCan(t *testing.T) {
	arm := compile(t, "scanner.bicep")
	vars, _ := arm["variables"].(map[string]any)

	// Bicep cannot reference a var in a parameter default, so the tag is written twice and this
	// is what keeps the two copies equal.
	def := param(t, arm, "image")["defaultValue"]
	if vars["defaultImage"] != def {
		t.Errorf("var defaultImage = %#v but param image defaults to %#v; the two must match", vars["defaultImage"], def)
	}
	if _, ok := vars["defaultImageUploads"].(bool); !ok {
		t.Fatalf("var defaultImageUploads = %#v, want a bool literal", vars["defaultImageUploads"])
	}

	// The module gets the image through the guard, never straight from the parameter.
	mod := resource(t, arm, "Microsoft.Resources/deployments")
	if !strings.Contains(mod, `"image":{"value":"[variables('guardedImage')]"}`) {
		t.Errorf("the module is not passed variables('guardedImage'); it must not bypass the upload guard")
	}
	guard, _ := vars["guardedImage"].(string)
	for what, want := range map[string]string{
		"upload requested":            `not(empty(parameters('parityApiUrl')))`,
		"with the default image":      `equals(parameters('image'), variables('defaultImage'))`,
		"that cannot upload":          `not(variables('defaultImageUploads'))`,
		"refuses the deployment":      `fail(`,
		"and names the commit needed": `8c30031`,
		"else passes the image":       `parameters('image'))]`,
	} {
		if !strings.Contains(guard, want) {
			t.Errorf("guardedImage does not guard on %s: missing %q in %q", what, want, guard)
		}
	}
}

// The template guard only knows the default image. A customer who mirrored an old tag into their
// own registry (the comment above `image` tells them to) passes a different string and gets past
// it, so the upload command asks the binary itself before scanning: a scanner without the
// -api-url flag reads neither variable, and the job exits 1 at start rather than reporting a
// success that delivered nothing. The file-share command is untouched; every binary can do that.
func TestUploadCommandProbesTheImageFirst(t *testing.T) {
	arm := compile(t, "scanner-resources.bicep")
	job := resource(t, arm, "Microsoft.App/jobs")

	probe := `scanner scan -h 2>&1 | grep -q -- -api-url || {`
	if !strings.Contains(job, probe) {
		t.Fatalf("the upload command does not probe the binary for -api-url: missing %q", probe)
	}
	for what, want := range map[string]string{
		"fails the execution": `exit 1; }; scanner scan --subscription`,
		"says which commit":   `8c30031`,
	} {
		if !strings.Contains(job, want) {
			t.Errorf("the probe does not %s: missing %q", what, want)
		}
	}
	share := `createArray('scanner scan --subscription \"$TARGET_SUBSCRIPTION\" --exclude-groups \"$OWN_RESOURCE_GROUP\" > /estate/estate.json`
	if !strings.Contains(job, share) {
		t.Errorf("the file-share command should run the scan directly, without a probe: missing %q", share)
	}
}
