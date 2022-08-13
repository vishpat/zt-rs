terraform {
  backend "local" {
    path = "terraform.tfstate"
  }
}


provider "vault" {
}

# Enable Auditing

resource "vault_audit" "test" {
  type = "file"

  options = {
    file_path = "/tmp/audit.txt"
  }
}

# Enable version 1 kv store

resource "vault_mount" "kv" {
  path        = "kv"
  type        = "kv-v1"
  description = "Key-Value store"
}


# Enable JWT authentication 

resource "vault_jwt_auth_backend" "jwt_auth" {
    description = "Enable JWT auth"
    path = "jwt"
    jwks_url = "http://localhost:8080/auth/jwks"
}

# Role for Alice to access key private secrets

resource "vault_jwt_auth_backend_role" "jwt_alice" {
  backend        = vault_jwt_auth_backend.jwt_auth.path
  role_name      = "jwt_alice"
  token_policies = ["alice_policy"]


  bound_subject   = "alice"
  user_claim      = "sub"
  role_type       = "jwt"
}

resource "vault_policy" "alice_policy" {
  name   = "alice_policy"
  policy = <<EOT

path "secret/kv/users/alice/*" {
    capabilities = [ "create", "read", 
        "update", "delete", "list" ]
}

                EOT
}

## Role to access the eng secrets
## 
#resource "vault_jwt_auth_backend_role" "jwt_eng" {
#  backend        = vault_jwt_auth_backend.jwt_auth.path
#  role_name      = "jwt_eng"
#  token_policies = ["eng_policy"]
#
#  groups_claim  = "eng"
#  user_claim      = "sub"
#  role_type       = "jwt"
#}
#
#resource "vault_policy" "eng_policy" {
#  name   = "eng_policy"
#  policy = <<EOT
#
#path "secret/kv/groups/eng/*" {
#    capabilities = [ "create", "read", 
#      "update", "delete", "list" ]
#}
#
#                EOT
#}
