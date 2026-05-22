package framework

import (
	"context"

	"github.com/hashicorp/terraform-plugin-framework/datasource"
	"github.com/hashicorp/terraform-plugin-framework/diag"
	"github.com/hashicorp/terraform-plugin-framework/ephemeral"
	"github.com/hashicorp/terraform-plugin-framework/provider"
	"github.com/hashicorp/terraform-plugin-framework/provider/schema"
	"github.com/hashicorp/terraform-plugin-framework/providerserver"
	"github.com/hashicorp/terraform-plugin-framework/resource"
	"github.com/hashicorp/terraform-plugin-go/tfprotov6"
)

// testVaultProvider is a minimal provider.Provider used in unit tests.
// It wires up only the vault data sources and ephemeral resources with an
// injectable vaultRunner so tests never require ansible-vault on PATH.
type testVaultProvider struct {
	runner vaultRunner
}

var _ provider.Provider = (*testVaultProvider)(nil)
var _ provider.ProviderWithEphemeralResources = (*testVaultProvider)(nil)

func (p *testVaultProvider) Metadata(_ context.Context, _ provider.MetadataRequest, resp *provider.MetadataResponse) {
	resp.TypeName = "ansible"
}

func (p *testVaultProvider) Schema(_ context.Context, _ provider.SchemaRequest, resp *provider.SchemaResponse) {
	resp.Schema = schema.Schema{}
}

func (p *testVaultProvider) Configure(_ context.Context, _ provider.ConfigureRequest, _ *provider.ConfigureResponse) {
}

func (p *testVaultProvider) DataSources(_ context.Context) []func() datasource.DataSource {
	runner := p.runner
	return []func() datasource.DataSource{
		func() datasource.DataSource { return &VaultDataSource{runner: runner} },
		func() datasource.DataSource { return &VaultStringDataSource{runner: runner} },
	}
}

func (p *testVaultProvider) Resources(_ context.Context) []func() resource.Resource {
	return nil
}

func (p *testVaultProvider) EphemeralResources(_ context.Context) []func() ephemeral.EphemeralResource {
	runner := p.runner
	return []func() ephemeral.EphemeralResource{
		func() ephemeral.EphemeralResource { return &VaultEphemeralResource{runner: runner} },
		func() ephemeral.EphemeralResource { return &VaultStringEphemeralResource{runner: runner} },
	}
}

// protoV6ProviderFactories returns a Protocol 6 provider factory for use with
// resource.UnitTest. The given runner is injected into all vault resources so
// tests control what ansible-vault "returns" without executing any process.
func protoV6ProviderFactories(runner vaultRunner) map[string]func() (tfprotov6.ProviderServer, error) {
	return map[string]func() (tfprotov6.ProviderServer, error){
		"ansible": providerserver.NewProtocol6WithError(&testVaultProvider{runner: runner}),
	}
}

// okRunner returns a vaultRunner that always succeeds with the given plaintext.
func okRunner(plaintext string) vaultRunner {
	return func(_ context.Context, _, _, _ string) (string, diag.Diagnostics) {
		return plaintext, nil
	}
}

// errRunner returns a vaultRunner that always fails with the given error.
func errRunner(summary, detail string) vaultRunner {
	return func(_ context.Context, _, _, _ string) (string, diag.Diagnostics) {
		var d diag.Diagnostics
		d.AddError(summary, detail)
		return "", d
	}
}
