# shared/backends/aws/main.tf
# Bootstraps S3 + DynamoDB remote state infrastructure.
# Run with local state first, then migrate if desired.

terraform {
  required_providers {
    aws = { source = "hashicorp/aws"; version = "~> 5.0" }
  }
}

provider "aws" {
  region = var.aws_region
}

data "aws_caller_identity" "current" {}

locals {
  bucket_name = "tfstate-${var.org_prefix}-${data.aws_caller_identity.current.account_id}"
}

# -- KMS Key for state encryption ----------------------------------------------
resource "aws_kms_key" "terraform_state" {
  description             = "KMS key for Terraform state encryption"
  deletion_window_in_days = 10
  enable_key_rotation     = true
  tags                    = { ManagedBy = "terraform"; Purpose = "terraform-state" }
}

resource "aws_kms_alias" "terraform_state" {
  name          = "alias/terraform-state"
  target_key_id = aws_kms_key.terraform_state.key_id
}

# -- S3 State Bucket ------------------------------------------------------------
resource "aws_s3_bucket" "terraform_state" {
  bucket        = local.bucket_name
  force_destroy = false
  tags          = { ManagedBy = "terraform"; Purpose = "terraform-state" }
}

resource "aws_s3_bucket_versioning" "terraform_state" {
  bucket = aws_s3_bucket.terraform_state.id
  versioning_configuration { status = "Enabled" }
}

resource "aws_s3_bucket_server_side_encryption_configuration" "terraform_state" {
  bucket = aws_s3_bucket.terraform_state.id
  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm     = "aws:kms"
      kms_master_key_id = aws_kms_key.terraform_state.arn
    }
    bucket_key_enabled = true
  }
}

resource "aws_s3_bucket_public_access_block" "terraform_state" {
  bucket                  = aws_s3_bucket.terraform_state.id
  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

resource "aws_s3_bucket_lifecycle_configuration" "terraform_state" {
  bucket = aws_s3_bucket.terraform_state.id
  rule {
    id     = "expire-old-versions"
    status = "Enabled"
    noncurrent_version_expiration { noncurrent_days = 90 }
  }
}

# -- DynamoDB Lock Table --------------------------------------------------------
resource "aws_dynamodb_table" "terraform_state_lock" {
  name         = "terraform-state-lock"
  billing_mode = "PAY_PER_REQUEST"
  hash_key     = "LockID"

  attribute {
    name = "LockID"
    type = "S"
  }

  server_side_encryption {
    enabled     = true
    kms_key_arn = aws_kms_key.terraform_state.arn
  }

  tags = { ManagedBy = "terraform"; Purpose = "terraform-state-lock" }
}

# -- Outputs --------------------------------------------------------------------
output "state_bucket_name" { value = aws_s3_bucket.terraform_state.id }
output "lock_table_name"   { value = aws_dynamodb_table.terraform_state_lock.name }
output "kms_key_arn"       { value = aws_kms_key.terraform_state.arn }
