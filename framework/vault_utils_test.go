package framework

import (
	"context"
	"os"
	"testing"

	"github.com/hashicorp/terraform-plugin-framework/diag"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// --- buildVaultViewArgs ---

func TestBuildVaultViewArgs_withoutVaultID(t *testing.T) {
	args := buildVaultViewArgs("/tmp/pass", "", "/tmp/secret.yml")
	assert.Equal(t, []string{"view", "--vault-password-file", "/tmp/pass", "/tmp/secret.yml"}, args)
}

func TestBuildVaultViewArgs_withVaultID(t *testing.T) {
	args := buildVaultViewArgs("/tmp/pass", "myid", "/tmp/secret.yml")
	assert.Equal(t, []string{"view", "--vault-id", "myid@/tmp/pass", "/tmp/secret.yml"}, args)
}

// --- buildVaultDecryptArgs ---

func TestBuildVaultDecryptArgs_withoutVaultID(t *testing.T) {
	args := buildVaultDecryptArgs("/tmp/pass", "")
	assert.Equal(t, []string{"decrypt", "--vault-password-file", "/tmp/pass", "--output=-", "-"}, args)
}

func TestBuildVaultDecryptArgs_withVaultID(t *testing.T) {
	args := buildVaultDecryptArgs("/tmp/pass", "myid")
	assert.Equal(t, []string{"decrypt", "--vault-id", "myid@/tmp/pass", "--output=-", "-"}, args)
}

// --- decryptVaultStringWith ---

func TestDecryptVaultStringWith_passesEncryptedContentToRunner(t *testing.T) {
	const encrypted = "$ANSIBLE_VAULT;1.1;AES256\nfakedata"

	var receivedContent string
	runner := func(_ context.Context, _, _, content string) (string, diag.Diagnostics) {
		receivedContent = content
		return "plaintext", diag.Diagnostics{}
	}

	got, diags := decryptVaultStringWith(context.Background(), encrypted, "/pass", "", runner)
	assert.False(t, diags.HasError())
	assert.Equal(t, "plaintext", got)
	assert.Equal(t, encrypted, receivedContent)
}

func TestDecryptVaultStringWith_forwardsPasswordFileAndVaultID(t *testing.T) {
	var gotPass, gotID string
	runner := func(_ context.Context, passwordFile, vaultID, _ string) (string, diag.Diagnostics) {
		gotPass = passwordFile
		gotID = vaultID
		return "ok", diag.Diagnostics{}
	}

	_, diags := decryptVaultStringWith(context.Background(), "enc", "/my/pass", "prod", runner)
	assert.False(t, diags.HasError())
	assert.Equal(t, "/my/pass", gotPass)
	assert.Equal(t, "prod", gotID)
}

func TestDecryptVaultStringWith_propagatesRunnerError(t *testing.T) {
	runner := func(_ context.Context, _, _, _ string) (string, diag.Diagnostics) {
		var d diag.Diagnostics
		d.AddError("decrypt failed", "bad password")
		return "", d
	}

	_, diags := decryptVaultStringWith(context.Background(), "enc", "/pass", "", runner)
	require.True(t, diags.HasError())
	assert.Equal(t, "decrypt failed", diags[0].Summary())
}

// --- resolvePasswordFile ---

func TestResolvePasswordFile_withVaultPasswordFile_returnsPathDirectly(t *testing.T) {
	path, cleanup, diags := resolvePasswordFile("", "/my/pass")
	defer cleanup()
	assert.False(t, diags.HasError())
	assert.Equal(t, "/my/pass", path)
}

func TestResolvePasswordFile_withVaultPassword_writesTempFile(t *testing.T) {
	path, cleanup, diags := resolvePasswordFile("mypassword", "")
	defer cleanup()
	require.False(t, diags.HasError())

	content, err := os.ReadFile(path)
	require.NoError(t, err)
	assert.Equal(t, "mypassword", string(content))
}

func TestResolvePasswordFile_withVaultPassword_cleanupRemovesTempFile(t *testing.T) {
	path, cleanup, diags := resolvePasswordFile("mypassword", "")
	require.False(t, diags.HasError())

	cleanup()

	_, err := os.Stat(path)
	assert.True(t, os.IsNotExist(err), "temp file %q should have been removed", path)
}

func TestResolvePasswordFile_bothSet_vaultPasswordTakesPrecedence(t *testing.T) {
	path, cleanup, diags := resolvePasswordFile("inlinepass", "/file/pass")
	defer cleanup()
	require.False(t, diags.HasError())

	// Should have written a temp file, not returned the file path directly.
	assert.NotEqual(t, "/file/pass", path)

	content, err := os.ReadFile(path)
	require.NoError(t, err)
	assert.Equal(t, "inlinepass", string(content))
}
