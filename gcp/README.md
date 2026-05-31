# GCP Security Configurations

## Contents

| Path | Description |
|------|-------------|
| `terraform/iam/` | Org-level IAM bindings, workload identity |
| `org-policies/` | Organization policy constraints |
| `landing-zone/` | Folder hierarchy, project factory |
| `scc-findings/` | Security Command Center custom findings |
| `scripts/` | gcloud / Python automation |

## Deployment

```bash
gcloud auth application-default login
cd gcp/terraform/iam
terraform init
terraform plan
terraform apply
```
