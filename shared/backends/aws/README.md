# AWS Terraform Remote State Backend

Uses S3 + DynamoDB for state storage and locking.

## Bootstrap (run once per account)

```bash
cd shared/backends/aws
terraform init
terraform apply
```

This creates:
- S3 bucket with versioning, encryption, and public-access block
- DynamoDB table for state locking
- KMS key for server-side encryption

## Usage in provider modules

After bootstrapping, reference in each Terraform root module:

```hcl
terraform {
  backend "s3" {
    bucket         = "your-org-tfstate-<account-id>"
    key            = "aws/scps/terraform.tfstate"
    region         = "us-east-1"
    encrypt        = true
    kms_key_id     = "alias/terraform-state"
    dynamodb_table = "terraform-state-lock"
  }
}
```
