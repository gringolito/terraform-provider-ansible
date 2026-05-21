//go:build integration

package framework

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const (
	integrationPassword  = "integration-test-password"
	integrationVaultID   = "inttest"
	integrationPlaintext = "hello: from vault!\na_number: 42\n"
)

// setup creates a temp dir with a vault password file and returns the dir path and cleanup func.
func integrationSetup(t *testing.T) (dir, passFile string) {
	t.Helper()

	if _, err := exec.LookPath("ansible-vault"); err != nil {
		t.Skip("ansible-vault not found in PATH — skipping integration tests")
	}

	dir = t.TempDir()
	passFile = filepath.Join(dir, "vault_pass")
	require.NoError(t, os.WriteFile(passFile, []byte(integrationPassword), 0o600))
	return
}

// encryptFile writes plaintext to a file and encrypts it in place with ansible-vault.
func encryptFile(t *testing.T, dir, passFile, filename, plaintext string) string {
	t.Helper()
	path := filepath.Join(dir, filename)
	require.NoError(t, os.WriteFile(path, []byte(plaintext), 0o600))
	out, err := exec.Command("ansible-vault", "encrypt", "--vault-password-file", passFile, path).CombinedOutput()
	require.NoError(t, err, "ansible-vault encrypt failed: %s", string(out))
	return path
}

// encryptFileWithID encrypts using a vault ID label.
func encryptFileWithID(t *testing.T, dir, passFile, vaultID, filename, plaintext string) string {
	t.Helper()
	path := filepath.Join(dir, filename)
	require.NoError(t, os.WriteFile(path, []byte(plaintext), 0o600))
	out, err := exec.Command("ansible-vault", "encrypt",
		"--vault-id", vaultID+"@"+passFile, path,
	).CombinedOutput()
	require.NoError(t, err, "ansible-vault encrypt failed: %s", string(out))
	return path
}

// TestVaultIntegration_FileDecrypt decrypts a real vault-encrypted file via vault_password_file.
func TestVaultIntegration_FileDecrypt(t *testing.T) {
	dir, passFile := integrationSetup(t)
	encrypted := encryptFile(t, dir, passFile, "secret.yml", integrationPlaintext)

	got, diags := runAnsibleVaultView(context.Background(), passFile, "", encrypted)
	require.False(t, diags.HasError(), "unexpected diagnostics: %v", diags)
	assert.Equal(t, integrationPlaintext, got)
}

// TestVaultIntegration_FileDecryptWithVaultID decrypts using a vault ID label.
func TestVaultIntegration_FileDecryptWithVaultID(t *testing.T) {
	dir, passFile := integrationSetup(t)
	encrypted := encryptFileWithID(t, dir, passFile, integrationVaultID, "secret_id.yml", integrationPlaintext)

	got, diags := runAnsibleVaultView(context.Background(), passFile, integrationVaultID, encrypted)
	require.False(t, diags.HasError(), "unexpected diagnostics: %v", diags)
	assert.Equal(t, integrationPlaintext, got)
}

// TestVaultIntegration_FileDecrypt_WrongPassword verifies an error is returned for a bad password.
func TestVaultIntegration_FileDecrypt_WrongPassword(t *testing.T) {
	dir, passFile := integrationSetup(t)
	encrypted := encryptFile(t, dir, passFile, "secret_bad.yml", integrationPlaintext)

	wrongPass := filepath.Join(dir, "wrong_pass")
	require.NoError(t, os.WriteFile(wrongPass, []byte("not-the-password"), 0o600))

	_, diags := runAnsibleVaultView(context.Background(), wrongPass, "", encrypted)
	assert.True(t, diags.HasError(), "expected an error for wrong password")
}

// TestVaultIntegration_StringDecrypt decrypts an inline vault string (reads encrypted file content as the string).
func TestVaultIntegration_StringDecrypt(t *testing.T) {
	dir, passFile := integrationSetup(t)
	encryptedFile := encryptFile(t, dir, passFile, "string_source.yml", integrationPlaintext)

	encryptedContent, err := os.ReadFile(encryptedFile)
	require.NoError(t, err)

	// Trim trailing newline added by ansible-vault to match plaintext exactly.
	got, diags := decryptVaultString(context.Background(), strings.TrimRight(string(encryptedContent), "\n"), passFile, "")
	require.False(t, diags.HasError(), "unexpected diagnostics: %v", diags)
	assert.Equal(t, integrationPlaintext, got)
}

// TestVaultIntegration_StringDecryptWithVaultID decrypts an inline vault string encrypted with a vault ID.
func TestVaultIntegration_StringDecryptWithVaultID(t *testing.T) {
	dir, passFile := integrationSetup(t)
	encryptedFile := encryptFileWithID(t, dir, passFile, integrationVaultID, "string_id_source.yml", integrationPlaintext)

	encryptedContent, err := os.ReadFile(encryptedFile)
	require.NoError(t, err)

	got, diags := decryptVaultString(context.Background(), strings.TrimRight(string(encryptedContent), "\n"), passFile, integrationVaultID)
	require.False(t, diags.HasError(), "unexpected diagnostics: %v", diags)
	assert.Equal(t, integrationPlaintext, got)
}
