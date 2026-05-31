# shared/backends/gcp/main.tf
# Bootstraps GCS remote state bucket with versioning and CMEK.

terraform {
  required_providers {
    google = { source = "hashicorp/google"; version = "~> 5.0" }
  }
}

provider "google" { project = var.project_id }

resource "google_kms_key_ring" "tfstate" {
  name     = "terraform-state-keyring"
  location = var.location
}

resource "google_kms_crypto_key" "tfstate" {
  name            = "terraform-state-key"
  key_ring        = google_kms_key_ring.tfstate.id
  rotation_period = "7776000s" # 90 days
}

resource "google_storage_bucket" "tfstate" {
  name                        = "tfstate-${var.org_prefix}-${var.project_id}"
  location                    = upper(var.location)
  force_destroy               = false
  uniform_bucket_level_access = true
  public_access_prevention    = "enforced"

  versioning { enabled = true }

  lifecycle_rule {
    condition { num_newer_versions = 10 }
    action    { type = "Delete" }
  }

  encryption {
    default_kms_key_name = google_kms_crypto_key.tfstate.id
  }
}

output "bucket_name" { value = google_storage_bucket.tfstate.name }
