package framework

import (
	"regexp"
	"testing"

	"github.com/hashicorp/terraform-plugin-testing/helper/resource"
)

func TestVaultDataSource_decryptsYaml(t *testing.T) {
	resource.UnitTest(t, resource.TestCase{
		ProtoV6ProviderFactories: protoV6ProviderFactories(okRunner("hello: world\n")),
		Steps: []resource.TestStep{
			{
				Config: `
data "ansible_vault" "test" {
  vault_file          = "/fake/vault.yml"
  vault_password_file = "/fake/pass"
}`,
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr("data.ansible_vault.test", "yaml", "hello: world\n"),
				),
			},
		},
	})
}

func TestVaultDataSource_withVaultID(t *testing.T) {
	resource.UnitTest(t, resource.TestCase{
		ProtoV6ProviderFactories: protoV6ProviderFactories(okRunner("secret: value\n")),
		Steps: []resource.TestStep{
			{
				Config: `
data "ansible_vault" "test" {
  vault_file          = "/fake/vault.yml"
  vault_password_file = "/fake/pass"
  vault_id            = "prod"
}`,
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr("data.ansible_vault.test", "yaml", "secret: value\n"),
				),
			},
		},
	})
}

func TestVaultDataSource_propagatesDecryptError(t *testing.T) {
	resource.UnitTest(t, resource.TestCase{
		ProtoV6ProviderFactories: protoV6ProviderFactories(errRunner("ansible-vault view failed", "ERROR! Decryption failed (no vault secrets would decrypt)")),
		Steps: []resource.TestStep{
			{
				Config: `
data "ansible_vault" "test" {
  vault_file          = "/fake/vault.yml"
  vault_password_file = "/fake/wrong-pass"
}`,
				ExpectError: regexp.MustCompile(`ansible-vault view failed`),
			},
		},
	})
}

func TestVaultDataSource_withVaultPassword(t *testing.T) {
	resource.UnitTest(t, resource.TestCase{
		ProtoV6ProviderFactories: protoV6ProviderFactories(okRunner("hello: world\n")),
		Steps: []resource.TestStep{
			{
				Config: `
data "ansible_vault" "test" {
  vault_file     = "/fake/vault.yml"
  vault_password = "mypassword"
}`,
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr("data.ansible_vault.test", "yaml", "hello: world\n"),
				),
			},
		},
	})
}

func TestVaultDataSource_missingBothPasswordOptions(t *testing.T) {
	resource.UnitTest(t, resource.TestCase{
		ProtoV6ProviderFactories: protoV6ProviderFactories(okRunner("")),
		Steps: []resource.TestStep{
			{
				Config: `
data "ansible_vault" "test" {
  vault_file = "/fake/vault.yml"
}`,
				ExpectError: regexp.MustCompile(`Invalid Attribute Combination`),
			},
		},
	})
}

func TestVaultDataSource_computedYamlWithInputsInState(t *testing.T) {
	// Terraform always writes config attributes into data source state (it uses them
	// to detect when a re-read is needed). Only `yaml` is provider-computed; the
	// other attributes are echoed from config. For portability across machines use
	// the ansible_vault ephemeral resource instead, which stores nothing.
	resource.UnitTest(t, resource.TestCase{
		ProtoV6ProviderFactories: protoV6ProviderFactories(okRunner("data")),
		Steps: []resource.TestStep{
			{
				Config: `
data "ansible_vault" "test" {
  vault_file          = "/fake/vault.yml"
  vault_password_file = "/fake/pass"
}`,
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr("data.ansible_vault.test", "yaml", "data"),
				),
			},
		},
	})
}
