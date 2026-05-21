package framework

import (
	"context"
	"os"
	"os/exec"

	"github.com/hashicorp/terraform-plugin-framework/diag"
)

// buildVaultViewArgs returns the ansible-vault view arguments for the given inputs.
// When vaultID is non-empty it uses --vault-id <id>@<passwordFile>; otherwise --vault-password-file.
func buildVaultViewArgs(passwordFile, vaultID, vaultFile string) []string {
	if vaultID != "" {
		return []string{"view", "--vault-id", vaultID + "@" + passwordFile, vaultFile}
	}
	return []string{"view", "--vault-password-file", passwordFile, vaultFile}
}

// runAnsibleVaultView runs `ansible-vault view` against vaultFile and returns the decrypted content.
func runAnsibleVaultView(ctx context.Context, passwordFile, vaultID, vaultFile string) (string, diag.Diagnostics) {
	var diags diag.Diagnostics

	args := buildVaultViewArgs(passwordFile, vaultID, vaultFile)
	out, err := exec.CommandContext(ctx, "ansible-vault", args...).CombinedOutput()
	if err != nil {
		diags.AddError("ansible-vault view failed", string(out))
		return "", diags
	}

	return string(out), diags
}

type vaultRunner func(ctx context.Context, passwordFile, vaultID, vaultFile string) (string, diag.Diagnostics)

// decryptVaultString writes the encrypted vault string to a temp file and decrypts it via runner.
func decryptVaultString(ctx context.Context, encryptedContent, passwordFile, vaultID string) (string, diag.Diagnostics) {
	return decryptVaultStringWith(ctx, encryptedContent, passwordFile, vaultID, runAnsibleVaultView)
}

func decryptVaultStringWith(ctx context.Context, encryptedContent, passwordFile, vaultID string, runner vaultRunner) (string, diag.Diagnostics) {
	var diags diag.Diagnostics

	tmpFile, err := os.CreateTemp("", "ansible-vault-string-*")
	if err != nil {
		diags.AddError("Failed to create temp file", err.Error())
		return "", diags
	}
	defer os.Remove(tmpFile.Name())

	if _, err := tmpFile.WriteString(encryptedContent); err != nil {
		tmpFile.Close()
		diags.AddError("Failed to write vault string to temp file", err.Error())
		return "", diags
	}
	tmpFile.Close()

	return runner(ctx, passwordFile, vaultID, tmpFile.Name())
}
