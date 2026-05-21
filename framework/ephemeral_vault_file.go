package framework

import (
	"context"

	"github.com/hashicorp/terraform-plugin-framework/ephemeral"
	ephemeralschema "github.com/hashicorp/terraform-plugin-framework/ephemeral/schema"
	"github.com/hashicorp/terraform-plugin-framework/types"
)

var _ ephemeral.EphemeralResource = (*VaultFileEphemeralResource)(nil)

type VaultFileEphemeralResource struct{}

func NewVaultFileEphemeralResource() ephemeral.EphemeralResource {
	return &VaultFileEphemeralResource{}
}

func (e *VaultFileEphemeralResource) Metadata(
	_ context.Context,
	req ephemeral.MetadataRequest,
	resp *ephemeral.MetadataResponse,
) {
	resp.TypeName = req.ProviderTypeName + "_vault_file"
}

type vaultFileEphemeralModel struct {
	Path              types.String `tfsdk:"path"`
	VaultPasswordFile types.String `tfsdk:"vault_password_file"`
	VaultID           types.String `tfsdk:"vault_id"`
	Content           types.String `tfsdk:"content"`
}

func (e *VaultFileEphemeralResource) Schema(
	_ context.Context,
	_ ephemeral.SchemaRequest,
	resp *ephemeral.SchemaResponse,
) {
	resp.Schema = ephemeralschema.Schema{
		MarkdownDescription: "Decrypts an ansible-vault encrypted file and exposes its content. " +
			"Unlike the data source variant, this ephemeral resource writes nothing to state.",
		Attributes: map[string]ephemeralschema.Attribute{
			"path": ephemeralschema.StringAttribute{
				MarkdownDescription: "Path to the ansible-vault encrypted file.",
				Required:            true,
			},
			"vault_password_file": ephemeralschema.StringAttribute{
				MarkdownDescription: "Path to the file containing the vault password.",
				Required:            true,
				Sensitive:           true,
			},
			"vault_id": ephemeralschema.StringAttribute{
				MarkdownDescription: "Vault ID label used with `--vault-id <id>@<vault_password_file>`.",
				Optional:            true,
			},
			"content": ephemeralschema.StringAttribute{
				MarkdownDescription: "Decrypted content of the vault file.",
				Computed:            true,
				Sensitive:           true,
			},
		},
	}
}

func (e *VaultFileEphemeralResource) Open(ctx context.Context, req ephemeral.OpenRequest, resp *ephemeral.OpenResponse) {
	var config vaultFileEphemeralModel
	resp.Diagnostics.Append(req.Config.Get(ctx, &config)...)
	if resp.Diagnostics.HasError() {
		return
	}

	content, diags := runAnsibleVaultView(
		ctx,
		config.VaultPasswordFile.ValueString(),
		config.VaultID.ValueString(),
		config.Path.ValueString(),
	)
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}

	config.Content = types.StringValue(content)
	resp.Diagnostics.Append(resp.Result.Set(ctx, &config)...)
}
