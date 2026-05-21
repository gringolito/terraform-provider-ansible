package framework

import (
	"context"
	"testing"

	"github.com/hashicorp/terraform-plugin-framework/ephemeral"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestVaultStringEphemeralResource_Metadata(t *testing.T) {
	er := NewVaultStringEphemeralResource()
	var resp ephemeral.MetadataResponse
	er.Metadata(context.Background(), ephemeral.MetadataRequest{ProviderTypeName: "ansible"}, &resp)
	assert.Equal(t, "ansible_vault_string", resp.TypeName)
}

func TestVaultStringEphemeralResource_Schema(t *testing.T) {
	er := &VaultStringEphemeralResource{}
	var resp ephemeral.SchemaResponse
	er.Schema(context.Background(), ephemeral.SchemaRequest{}, &resp)
	require.Empty(t, resp.Diagnostics)

	attrs := resp.Schema.Attributes

	content := attrs["content"]
	require.NotNil(t, content)
	assert.True(t, content.IsRequired(), "content must be required")
	assert.False(t, content.IsComputed(), "content must not be computed")
	assert.False(t, content.IsSensitive(), "content must not be sensitive")

	passFile := attrs["vault_password_file"]
	require.NotNil(t, passFile)
	assert.True(t, passFile.IsRequired(), "vault_password_file must be required")
	assert.True(t, passFile.IsSensitive(), "vault_password_file must be sensitive")

	vaultID := attrs["vault_id"]
	require.NotNil(t, vaultID)
	assert.True(t, vaultID.IsOptional(), "vault_id must be optional")

	plaintext := attrs["plaintext"]
	require.NotNil(t, plaintext)
	assert.True(t, plaintext.IsComputed(), "plaintext must be computed")
	assert.True(t, plaintext.IsSensitive(), "plaintext must be sensitive")
}
