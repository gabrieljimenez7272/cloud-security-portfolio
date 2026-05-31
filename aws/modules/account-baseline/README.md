# AWS Account Baseline Module

Applied to every new AWS account via Control Tower Account Factory for Terraform (AFT)
or called directly after account creation.

## What it configures

| Resource | Purpose |
|----------|---------|
| CloudTrail (org trail) | API audit logging to central S3 |
| AWS Config | Resource configuration recording |
| Security Hub | Aggregated findings (CIS, FSBP standards) |
| GuardDuty | Threat detection, delegated to security account |
| IAM Password Policy | CIS-compliant password requirements |
| Default VPC removal | Deletes the default VPC in all regions |
| EBS encryption default | Enforces EBS encryption on all new volumes |
| S3 account-level block | Blocks all public S3 access at account level |

## Usage

```hcl
module "account_baseline" {
  source = "../../modules/account-baseline"

  account_name          = "workload-prod"
  environment           = "prod"
  security_account_id   = "123456789012"
  log_archive_bucket    = "org-cloudtrail-logs-123456789012"
  home_region           = "us-east-1"
}
```
