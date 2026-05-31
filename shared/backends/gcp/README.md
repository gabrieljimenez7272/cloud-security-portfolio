# GCP Terraform Remote State Backend

Uses a GCS bucket with versioning and CMEK encryption.

## Bootstrap (run once)

```bash
cd shared/backends/gcp
terraform init
terraform apply -var="project_id=your-project" -var="org_prefix=acme"
```

## Usage in provider modules

```hcl
terraform {
  backend "gcs" {
    bucket = "tfstate-acme-your-project"
    prefix = "gcp/iam"
  }
}
```
