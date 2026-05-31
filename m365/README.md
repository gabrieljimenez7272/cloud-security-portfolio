# Microsoft 365 Security Configurations

## Contents

| Path | Description |
|------|-------------|
| `conditional-access/` | CA policy JSON exports + deployment scripts |
| `dlp-policies/` | Data Loss Prevention policy templates |
| `compliance/` | Purview compliance baselines |
| `defender/` | Defender for Office 365 configurations |
| `scripts/` | PowerShell automation via Microsoft Graph |

## Notes

Most M365 configs are deployed via PowerShell + Microsoft Graph API rather than Terraform,
as the Terraform AzureAD provider has limited M365 coverage.

Exported JSON policies serve as version-controlled snapshots of production configs.
