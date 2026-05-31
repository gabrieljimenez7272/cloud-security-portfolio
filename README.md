# Cloud Security Portfolio

> Terraform configurations, IAM policies, SCPs, landing zones, and automation scripts across major cloud providers and SaaS platforms.

## Providers

| Folder | Platform | Key Content |
|--------|----------|-------------|
| [`aws/`](./aws) | Amazon Web Services | SCPs, IAM, Control Tower landing zone |
| [`azure/`](./azure) | Microsoft Azure | Policy, RBAC, Defender, landing zone |
| [`gcp/`](./gcp) | Google Cloud | Org policies, IAM, landing zone |
| [`m365/`](./m365) | Microsoft 365 | Conditional Access, DLP, Purview |
| [`entra-id/`](./entra-id) | Microsoft Entra ID | PIM, CA policies, auth methods |
| [`shared/`](./shared) | Cross-provider | Reusable modules, tagging standards |
| [`scripts/`](./scripts) | Automation | PowerShell & Python utilities |

## Framework Mappings

Configs in this repo are mapped to:
- **CIS Benchmarks** (AWS, Azure, GCP, M365)
- **NIST SP 800-53 Rev 5**
- **Microsoft Zero Trust Framework**

## Prerequisites

- Terraform >= 1.5
- AWS CLI / Azure CLI / gcloud CLI configured
- Python 3.10+ (for scripts)
- PowerShell 7+ with Microsoft.Graph module (for M365/Entra scripts)

## CI/CD

Pull requests run `tflint`, `tfsec`, and `checkov` automatically via GitHub Actions.
See [`.github/workflows/`](./.github/workflows/).

## Usage

Each subfolder has its own `README.md` with deployment instructions and control mappings.

## License

MIT
