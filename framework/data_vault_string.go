package framework

import (
	"context"
	"fmt"

	"github.com/hashicorp/terraform-plugin-framework/datasource"
	"github.com/hashicorp/terraform-plugin-framework/datasource/schema"
	"github.com/hashicorp/terraform-plugin-framework/types"
)

var _ datasource.DataSource = (*VaultStringDataSource)(nil)
var _ datasource.DataSourceWithConfigure = (*VaultStringDataSource)(nil)

type VaultStringDataSource struct {
	runner VaultRunner
}

func NewVaultStringDataSource() datasource.DataSource {
	return &VaultStringDataSource{runner: DefaultVaultRunner}
}

func (d *VaultStringDataSource) Configure(
	_ context.Context,
	req datasource.ConfigureRequest,
	resp *datasource.ConfigureResponse,
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
	d.runner = runner
}

func (d *VaultStringDataSource) Metadata(
	_ context.Context,
	req datasource.MetadataRequest,
	resp *datasource.MetadataResponse,
) {
	resp.TypeName = req.ProviderTypeName + "_vault_string"
}

type vaultStringConfigModel struct {
	Content           types.String `tfsdk:"content"`
	VaultPasswordFile types.String `tfsdk:"vault_password_file"`
	VaultID           types.String `tfsdk:"vault_id"`
	Plaintext         types.String `tfsdk:"plaintext"`
}

func (d *VaultStringDataSource) Schema(
	_ context.Context,
	_ datasource.SchemaRequest,
	resp *datasource.SchemaResponse,
) {
	resp.Schema = schema.Schema{
		MarkdownDescription: "Decrypts an ansible-vault encrypted string and exposes its plaintext.",
		Attributes: map[string]schema.Attribute{
			"content": schema.StringAttribute{
				MarkdownDescription: "The ansible-vault encrypted string (begins with `$ANSIBLE_VAULT;...`).",
				Required:            true,
			},
			"vault_password_file": schema.StringAttribute{
				MarkdownDescription: "Path to the file containing the vault password.",
				Required:            true,
				Sensitive:           true,
			},
			"vault_id": schema.StringAttribute{
				MarkdownDescription: "Vault ID label used with `--vault-id <id>@<vault_password_file>`.",
				Optional:            true,
			},
			"plaintext": schema.StringAttribute{
				MarkdownDescription: "Decrypted plaintext of the vault string.",
				Computed:            true,
				Sensitive:           true,
			},
		},
	}
}

func (d *VaultStringDataSource) Read(ctx context.Context, req datasource.ReadRequest, resp *datasource.ReadResponse) {
	var config vaultStringConfigModel
	resp.Diagnostics.Append(req.Config.Get(ctx, &config)...)
	if resp.Diagnostics.HasError() {
		return
	}

	plaintext, diags := decryptVaultStringWith(ctx, config.Content.ValueString(), config.VaultPasswordFile.ValueString(), config.VaultID.ValueString(), d.runner)
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}

	config.Plaintext = types.StringValue(plaintext)
	resp.Diagnostics.Append(resp.State.Set(ctx, &config)...)
}
