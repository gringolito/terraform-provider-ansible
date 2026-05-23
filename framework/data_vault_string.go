package framework

import (
	"context"

	"github.com/hashicorp/terraform-plugin-framework-validators/stringvalidator"
	"github.com/hashicorp/terraform-plugin-framework/datasource"
	"github.com/hashicorp/terraform-plugin-framework/datasource/schema"
	"github.com/hashicorp/terraform-plugin-framework/path"
	"github.com/hashicorp/terraform-plugin-framework/schema/validator"
	"github.com/hashicorp/terraform-plugin-framework/types"
)

var _ datasource.DataSource = (*VaultStringDataSource)(nil)

type VaultStringDataSource struct {
	runner vaultRunner
}

func NewVaultStringDataSource() datasource.DataSource {
	return &VaultStringDataSource{runner: runAnsibleVaultDecrypt}
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
	VaultPassword     types.String `tfsdk:"vault_password"`
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
			"vault_password": schema.StringAttribute{
				MarkdownDescription: "Vault password as a plain string.",
				Optional:            true,
				Sensitive:           true,
				Validators: []validator.String{
					stringvalidator.ConflictsWith(path.MatchRoot("vault_password_file")),
					stringvalidator.AtLeastOneOf(path.MatchRoot("vault_password"), path.MatchRoot("vault_password_file")),
				},
			},
			"vault_password_file": schema.StringAttribute{
				MarkdownDescription: "Path to the file containing the vault password.",
				Optional:            true,
				Sensitive:           true,
				Validators: []validator.String{
					stringvalidator.ConflictsWith(path.MatchRoot("vault_password")),
					stringvalidator.AtLeastOneOf(path.MatchRoot("vault_password"), path.MatchRoot("vault_password_file")),
				},
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

	passwordFile, cleanup, diags := resolvePasswordFile(config.VaultPassword.ValueString(), config.VaultPasswordFile.ValueString())
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}
	defer cleanup()

	plaintext, diags := decryptVaultStringWith(ctx, config.Content.ValueString(), passwordFile, config.VaultID.ValueString(), d.runner)
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}

	config.Plaintext = types.StringValue(plaintext)
	resp.Diagnostics.Append(resp.State.Set(ctx, &config)...)
}
