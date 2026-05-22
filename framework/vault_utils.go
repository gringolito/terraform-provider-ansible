package framework

import (
	"context"
	"os"
	"os/exec"
	"strings"

	"github.com/hashicorp/terraform-plugin-framework/diag"
)

// resolvePasswordFile returns the effective password file path from either an inline vault_password
// string or an explicit vault_password_file path.
// When vault_password is used, it is written to a temp file; the caller must invoke the returned
// cleanup func when done.
func resolvePasswordFile(vaultPassword, vaultPasswordFile string) (string, func(), diag.Diagnostics) {
	var diags diag.Diagnostics
	noop := func() {}

	if vaultPassword != "" {
		tmpFile, err := os.CreateTemp("", "ansible-vault-pass-*")
		if err != nil {
			diags.AddError("Failed to create temp password file", err.Error())
			return "", noop, diags
		}
		if _, err := tmpFile.WriteString(vaultPassword); err != nil {
			tmpFile.Close()
			os.Remove(tmpFile.Name())
			diags.AddError("Failed to write vault password to temp file", err.Error())
			return "", noop, diags
		}
		tmpFile.Close()
		path := tmpFile.Name()
		return path, func() { os.Remove(path) }, diags
	}

	return vaultPasswordFile, noop, diags
}

// buildVaultViewArgs returns the ansible-vault view arguments for the given inputs.
// When vaultID is non-empty it uses --vault-id <id>@<passwordFile>; otherwise --vault-password-file.
func buildVaultViewArgs(passwordFile, vaultID, vaultFile string) []string {
	if vaultID != "" {
		return []string{"view", "--vault-id", vaultID + "@" + passwordFile, vaultFile}
	}
	return []string{"view", "--vault-password-file", passwordFile, vaultFile}
}

// buildVaultDecryptArgs returns the ansible-vault decrypt arguments that read from stdin and write to stdout.
func buildVaultDecryptArgs(passwordFile, vaultID string) []string {
	if vaultID != "" {
		return []string{"decrypt", "--vault-id", vaultID + "@" + passwordFile, "--output=-", "-"}
	}
	return []string{"decrypt", "--vault-password-file", passwordFile, "--output=-", "-"}
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

// runAnsibleVaultDecrypt runs `ansible-vault decrypt` with encryptedContent on stdin and returns the plaintext.
// Stdout and stderr are captured separately so the "Decryption successful" status line on stderr is not included in the output.
func runAnsibleVaultDecrypt(ctx context.Context, passwordFile, vaultID, encryptedContent string) (string, diag.Diagnostics) {
	var diags diag.Diagnostics
	var stderr strings.Builder

	args := buildVaultDecryptArgs(passwordFile, vaultID)
	cmd := exec.CommandContext(ctx, "ansible-vault", args...)
	cmd.Stdin = strings.NewReader(encryptedContent)
	cmd.Stderr = &stderr
	stdout, err := cmd.Output()
	if err != nil {
		diags.AddError("ansible-vault decrypt failed", stderr.String())
		return "", diags
	}

	return string(stdout), diags
}

type vaultRunner func(ctx context.Context, passwordFile, vaultID, vaultTarget string) (string, diag.Diagnostics)

func decryptVaultStringWith(ctx context.Context, encryptedContent, passwordFile, vaultID string, runner vaultRunner) (string, diag.Diagnostics) {
	return runner(ctx, passwordFile, vaultID, encryptedContent)
}
