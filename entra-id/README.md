# Microsoft Entra ID Configurations

## Contents

| Path | Description |
|------|-------------|
| `terraform/apps/` | App registrations and service principals |
| `pim-roles/` | Privileged Identity Management role settings |
| `named-locations/` | Trusted IP/country locations for CA policies |
| `auth-methods/` | Authentication method policies (FIDO2, MFA) |
| `scripts/` | Graph API automation scripts |

## Notes

Uses `hashicorp/azuread` Terraform provider for app registrations and group configs.
PIM and auth method policies use PowerShell + Microsoft Graph.
