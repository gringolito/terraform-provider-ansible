package framework

import (
	"context"
	"os"
	"os/exec"

	"github.com/hashicorp/terraform-plugin-framework/diag"
)

// VaultRunner abstracts the ansible-vault invocation so tests can inject a mock.
type VaultRunner interface {
	View(ctx context.Context, passwordFile, vaultID, vaultFile string) (string, diag.Diagnostics)
}

type ansibleVaultRunner struct{}

// DefaultVaultRunner is the production VaultRunner that shells out to ansible-vault.
var DefaultVaultRunner VaultRunner = &ansibleVaultRunner{}

func (r *ansibleVaultRunner) View(ctx context.Context, passwordFile, vaultID, vaultFile string) (string, diag.Diagnostics) {
	var diags diag.Diagnostics

	args := buildVaultViewArgs(passwordFile, vaultID, vaultFile)
	out, err := exec.CommandContext(ctx, "ansible-vault", args...).CombinedOutput()
	if err != nil {
		diags.AddError("ansible-vault view failed", string(out))
		return "", diags
	}

	return string(out), diags
}

// buildVaultViewArgs returns the ansible-vault view arguments for the given inputs.
// When vaultID is non-empty it uses --vault-id <id>@<passwordFile>; otherwise --vault-password-file.
func buildVaultViewArgs(passwordFile, vaultID, vaultFile string) []string {
	if vaultID != "" {
		return []string{"view", "--vault-id", vaultID + "@" + passwordFile, vaultFile}
	}
	return []string{"view", "--vault-password-file", passwordFile, vaultFile}
}

// decryptVaultStringWith writes the encrypted vault string to a temp file and decrypts it via runner.
func decryptVaultStringWith(ctx context.Context, encryptedContent, passwordFile, vaultID string, runner VaultRunner) (string, diag.Diagnostics) {
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

	return runner.View(ctx, passwordFile, vaultID, tmpFile.Name())
}
