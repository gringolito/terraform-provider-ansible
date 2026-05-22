package framework

import (
	"context"
	"fmt"

	"github.com/hashicorp/terraform-plugin-framework/ephemeral"
	ephemeralschema "github.com/hashicorp/terraform-plugin-framework/ephemeral/schema"
	"github.com/hashicorp/terraform-plugin-framework/types"
)

var _ ephemeral.EphemeralResource = (*VaultStringEphemeralResource)(nil)
var _ ephemeral.EphemeralResourceWithConfigure = (*VaultStringEphemeralResource)(nil)

type VaultStringEphemeralResource struct {
	runner VaultRunner
}

func NewVaultStringEphemeralResource() ephemeral.EphemeralResource {
	return &VaultStringEphemeralResource{runner: DefaultVaultRunner}
}

func (e *VaultStringEphemeralResource) Configure(
	_ context.Context,
	req ephemeral.ConfigureRequest,
	resp *ephemeral.ConfigureResponse,
) {
	if req.ProviderData == nil {
		return
	}
	runner, ok := req.ProviderData.(VaultRunner)
	if !ok {
		resp.Diagnostics.AddError(
			"Unexpected ProviderData type",
			fmt.Sprintf("expected VaultRunner, got %T", req.ProviderData),
		)
		return
	}
	e.runner = runner
}

func (e *VaultStringEphemeralResource) Metadata(
	_ context.Context,
	req ephemeral.MetadataRequest,
	resp *ephemeral.MetadataResponse,
) {
	resp.TypeName = req.ProviderTypeName + "_vault_string"
}

type vaultStringEphemeralModel struct {
	Content           types.String `tfsdk:"content"`
	VaultPasswordFile types.String `tfsdk:"vault_password_file"`
	VaultID           types.String `tfsdk:"vault_id"`
	Plaintext         types.String `tfsdk:"plaintext"`
}

func (e *VaultStringEphemeralResource) Schema(
	_ context.Context,
	_ ephemeral.SchemaRequest,
	resp *ephemeral.SchemaResponse,
) {
	resp.Schema = ephemeralschema.Schema{
		MarkdownDescription: "Decrypts an ansible-vault encrypted string and exposes its plaintext. " +
			"Unlike the data source variant, this ephemeral resource writes nothing to state.",
		Attributes: map[string]ephemeralschema.Attribute{
			"content": ephemeralschema.StringAttribute{
				MarkdownDescription: "The ansible-vault encrypted string (begins with `$ANSIBLE_VAULT;...`).",
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
			"plaintext": ephemeralschema.StringAttribute{
				MarkdownDescription: "Decrypted plaintext of the vault string.",
				Computed:            true,
				Sensitive:           true,
			},
		},
	}
}

func (e *VaultStringEphemeralResource) Open(ctx context.Context, req ephemeral.OpenRequest, resp *ephemeral.OpenResponse) {
	var config vaultStringEphemeralModel
	resp.Diagnostics.Append(req.Config.Get(ctx, &config)...)
	if resp.Diagnostics.HasError() {
		return
	}

	plaintext, diags := decryptVaultStringWith(
		ctx,
		config.Content.ValueString(),
		config.VaultPasswordFile.ValueString(),
		config.VaultID.ValueString(),
		e.runner,
	)
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}

	config.Plaintext = types.StringValue(plaintext)
	resp.Diagnostics.Append(resp.Result.Set(ctx, &config)...)
}
