data "ansible_vault_file" "secret" {
  path               = "${path.module}/secrets/db_password.yml"
  vault_password_file = "${path.module}/.vault_pass"
}

output "db_password_yaml" {
  value     = data.ansible_vault_file.secret.content
  sensitive = true
}
