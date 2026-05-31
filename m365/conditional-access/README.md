# Conditional Access Policies

## Naming Convention

`CA-[number]-[audience]-[condition]-[control]`

Examples:
- `CA-001-AllUsers-AnyApp-RequireMFA`
- `CA-002-Guests-O365Apps-BlockLegacyAuth`
- `CA-003-Admins-AnyApp-RequireCompliantDevice`

## Baseline Policy Set (Microsoft recommended)

1. Require MFA for all users
2. Block legacy authentication
3. Require MFA for admins
4. Require compliant device for admins
5. Block high-risk sign-ins

See `policies/` for JSON exports of each.
