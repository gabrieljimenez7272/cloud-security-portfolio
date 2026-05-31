# Security Framework Mappings

Maps configurations in this repo to industry control frameworks.

## CIS Benchmark Coverage

| Config File | CIS Control | Benchmark |
|-------------|-------------|-----------|
| `aws/terraform/scps/policies/deny-root-actions.json` | 1.7 | CIS AWS v3.0 |
| `aws/terraform/scps/policies/deny-non-approved-regions.json` | 1.1 | CIS AWS v3.0 |
| `aws/terraform/scps/policies/protect-cloudtrail.json` | 3.1 | CIS AWS v3.0 |
| `azure/terraform/policies/require-https-storage` | 3.1 | CIS Azure v2.0 |
| `m365/conditional-access/policies/CA-001*` | 1.1 | CIS M365 v3.0 |
| `m365/conditional-access/policies/CA-002*` | 1.3 | CIS M365 v3.0 |

## NIST SP 800-53 Rev 5 Coverage

| Config | Control Family | Control |
|--------|---------------|---------|
| Require MFA (CA-001) | IA - Identification & Authentication | IA-2 |
| Block legacy auth (CA-002) | AC - Access Control | AC-17 |
| Protect CloudTrail | AU - Audit & Accountability | AU-9 |
| PIM role settings | AC - Access Control | AC-5, AC-6 |
| Deny root usage | AC - Access Control | AC-2 |
