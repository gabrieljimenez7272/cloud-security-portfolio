# aws/terraform/scps/scps-extended.tf
# Additional SCP policies: MFA enforcement, S3 hardening, GuardDuty, IAM escalation.

# -- Require MFA for Console Access --------------------------------------------
resource "aws_organizations_policy" "require_mfa_console" {
  name        = "RequireMFAForConsole"
  description = "Denies all non-MFA API calls except MFA self-enrollment actions. CIS 1.10"
  type        = "SERVICE_CONTROL_POLICY"
  content     = file("${path.module}/policies/require-mfa-for-console.json")
}

resource "aws_organizations_policy_attachment" "require_mfa_root" {
  policy_id = aws_organizations_policy.require_mfa_console.id
  target_id = var.org_root_id
}

# -- S3 Hardening ---------------------------------------------------------------
resource "aws_organizations_policy" "s3_hardening" {
  name        = "S3Hardening"
  description = "Blocks public ACLs, requires encryption, enforces TLS. CIS 2.1.1-2.1.5"
  type        = "SERVICE_CONTROL_POLICY"
  content     = file("${path.module}/policies/s3-hardening.json")
}

resource "aws_organizations_policy_attachment" "s3_hardening_root" {
  policy_id = aws_organizations_policy.s3_hardening.id
  target_id = var.org_root_id
}

# -- Protect GuardDuty ----------------------------------------------------------
resource "aws_organizations_policy" "protect_guardduty" {
  name        = "ProtectGuardDuty"
  description = "Prevents disabling or tampering with GuardDuty detectors. CIS 3.3"
  type        = "SERVICE_CONTROL_POLICY"
  content     = file("${path.module}/policies/enforce-guardduty.json")
}

resource "aws_organizations_policy_attachment" "protect_guardduty_root" {
  policy_id = aws_organizations_policy.protect_guardduty.id
  target_id = var.org_root_id
}

# -- Deny IAM Privilege Escalation ---------------------------------------------
resource "aws_organizations_policy" "deny_iam_escalation" {
  name        = "DenyIAMPrivilegeEscalation"
  description = "Blocks IAM escalation paths outside approved break-glass roles."
  type        = "SERVICE_CONTROL_POLICY"
  content     = file("${path.module}/policies/deny-iam-privilege-escalation.json")
}

resource "aws_organizations_policy_attachment" "deny_iam_escalation_root" {
  policy_id = aws_organizations_policy.deny_iam_escalation.id
  target_id = var.org_root_id
}
