# Cross-Provider Scripts

Utility scripts that work across multiple cloud providers.

| Script | Language | Description |
|--------|----------|-------------|
| `audit-mfa-coverage.ps1` | PowerShell | Checks MFA enrollment across Entra ID, AWS IAM |
| `export-ca-policies.ps1` | PowerShell | Exports all CA policies to JSON for version control |

## Requirements

- PowerShell 7+ with `Microsoft.Graph` module
- Python 3.10+ with `boto3`, `google-cloud-storage`
- Relevant CLI authenticated: `az`, `aws`, `gcloud`
