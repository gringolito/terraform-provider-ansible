package framework

import (
	"context"
	"testing"

	"github.com/hashicorp/terraform-plugin-framework/ephemeral"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestVaultFileEphemeralResource_Metadata(t *testing.T) {
	er := NewVaultFileEphemeralResource()
	var resp ephemeral.MetadataResponse
	er.Metadata(context.Background(), ephemeral.MetadataRequest{ProviderTypeName: "ansible"}, &resp)
	assert.Equal(t, "ansible_vault_file", resp.TypeName)
}

func TestVaultFileEphemeralResource_Schema(t *testing.T) {
	er := &VaultFileEphemeralResource{}
	var resp ephemeral.SchemaResponse
	er.Schema(context.Background(), ephemeral.SchemaRequest{}, &resp)
	require.Empty(t, resp.Diagnostics)

	attrs := resp.Schema.Attributes

	path := attrs["path"]
	require.NotNil(t, path)
	assert.True(t, path.IsRequired(), "path must be required")
	assert.False(t, path.IsComputed(), "path must not be computed")
	assert.False(t, path.IsSensitive(), "path must not be sensitive")

	passFile := attrs["vault_password_file"]
	require.NotNil(t, passFile)
	assert.True(t, passFile.IsRequired(), "vault_password_file must be required")
	assert.True(t, passFile.IsSensitive(), "vault_password_file must be sensitive")

	vaultID := attrs["vault_id"]
	require.NotNil(t, vaultID)
	assert.True(t, vaultID.IsOptional(), "vault_id must be optional")

	content := attrs["content"]
	require.NotNil(t, content)
	assert.True(t, content.IsComputed(), "content must be computed")
	assert.True(t, content.IsSensitive(), "content must be sensitive")
}
