package framework

import (
	"context"

	"github.com/hashicorp/terraform-plugin-framework/datasource"
	"github.com/hashicorp/terraform-plugin-framework/datasource/schema"
	"github.com/hashicorp/terraform-plugin-framework/types"
)

var _ datasource.DataSource = (*VaultFileDataSource)(nil)

type VaultFileDataSource struct{}

func NewVaultFileDataSource() datasource.DataSource {
	return &VaultFileDataSource{}
}

func (d *VaultFileDataSource) Metadata(
	_ context.Context,
	req datasource.MetadataRequest,
	resp *datasource.MetadataResponse,
) {
	resp.TypeName = req.ProviderTypeName + "_vault_file"
}

type vaultFileConfigModel struct {
	Path              types.String `tfsdk:"path"`
	VaultPasswordFile types.String `tfsdk:"vault_password_file"`
	VaultID           types.String `tfsdk:"vault_id"`
	Content           types.String `tfsdk:"content"`
}

type vaultFileStateModel struct {
	Content types.String `tfsdk:"content"`
}

func (d *VaultFileDataSource) Schema(
	_ context.Context,
	_ datasource.SchemaRequest,
	resp *datasource.SchemaResponse,
) {
	resp.Schema = schema.Schema{
		MarkdownDescription: "Decrypts an ansible-vault encrypted file and exposes its content.",
		Attributes: map[string]schema.Attribute{
			"path": schema.StringAttribute{
				MarkdownDescription: "Path to the ansible-vault encrypted file.",
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
			"content": schema.StringAttribute{
				MarkdownDescription: "Decrypted content of the vault file.",
				Computed:            true,
				Sensitive:           true,
			},
		},
	}
}

func (d *VaultFileDataSource) Read(ctx context.Context, req datasource.ReadRequest, resp *datasource.ReadResponse) {
	var config vaultFileConfigModel
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

	resp.Diagnostics.Append(resp.State.Set(ctx, &vaultFileStateModel{
		Content: types.StringValue(content),
	})...)
}
