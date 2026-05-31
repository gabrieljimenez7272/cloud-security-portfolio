# gcp/terraform/iam/main.tf
# Org-level IAM bindings enforcing least privilege.

terraform {
  required_providers {
    google = {
      source  = "hashicorp/google"
      version = "~> 5.0"
    }
  }
}

provider "google" {
  project = var.project_id
}

# -- Deny service account key creation at org level -----------------------------
resource "google_organization_iam_deny_policy" "deny_sa_key_creation" {
  parent       = "organizations/${var.org_id}"
  name         = "deny-sa-key-creation"
  display_name = "Deny SA key creation for all users"

  rules {
    deny_rule {
      denied_principals = ["principalSet://goog/public:all"]
      denied_permissions = [
        "iam.googleapis.com/serviceAccountKeys.create"
      ]
    }
  }
}
