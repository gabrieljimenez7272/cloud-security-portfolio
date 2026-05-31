# AWS Security Configurations

## Contents

| Path | Description |
|------|-------------|
| `terraform/scps/` | Service Control Policies (Org-level guardrails) |
| `terraform/iam/` | IAM roles, policies, and permission boundaries |
| `landing-zone/` | Control Tower baseline, account vending |
| `policies/` | Resource-based and trust policies |
| `scripts/` | AWS automation (Python/PowerShell) |

## CIS Benchmark Mappings

Selected configs map to CIS AWS Foundations Benchmark v3.0.

## Deployment

```bash
cd aws/terraform/scps
terraform init
terraform plan -out=tfplan
terraform apply tfplan
```
