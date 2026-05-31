# Azure Security Configurations

## Contents

| Path | Description |
|------|-------------|
| `terraform/policies/` | Azure Policy definitions and initiatives |
| `terraform/rbac/` | Custom RBAC role definitions |
| `landing-zone/` | Management group hierarchy, subscriptions |
| `defender/` | Defender for Cloud configurations |
| `scripts/` | Azure PowerShell / CLI automation |

## Deployment

Requires `az login` with Owner or Contributor rights on the target scope.

```bash
cd azure/terraform/policies
terraform init
terraform plan -var-file=prod.tfvars
terraform apply
```
