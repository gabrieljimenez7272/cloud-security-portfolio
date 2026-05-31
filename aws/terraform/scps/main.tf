# aws/terraform/scps/main.tf
# Org-level Service Control Policies applied via AWS Organizations.
# These are guardrails -- they restrict what even admin roles can do.

terraform {
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 5.0"
    }
  }
}

provider "aws" {
  region = var.aws_region
}

# -- Deny all actions outside approved regions ----------------------------------
resource "aws_organizations_policy" "deny_non_approved_regions" {
  name        = "DenyNonApprovedRegions"
  description = "Prevents resource creation outside approved regions. CIS 1.1"
  type        = "SERVICE_CONTROL_POLICY"
  content     = file("${path.module}/policies/deny-non-approved-regions.json")
}

resource "aws_organizations_policy_attachment" "deny_regions_root" {
  policy_id = aws_organizations_policy.deny_non_approved_regions.id
  target_id = var.org_root_id
}

# -- Deny root account usage ----------------------------------------------------
resource "aws_organizations_policy" "deny_root_actions" {
  name        = "DenyRootActions"
  description = "Blocks all root account API calls. CIS 1.7"
  type        = "SERVICE_CONTROL_POLICY"
  content     = file("${path.module}/policies/deny-root-actions.json")
}

resource "aws_organizations_policy_attachment" "deny_root_root" {
  policy_id = aws_organizations_policy.deny_root_actions.id
  target_id = var.org_root_id
}

# -- Prevent CloudTrail disable ------------------------------------------------
resource "aws_organizations_policy" "protect_cloudtrail" {
  name        = "ProtectCloudTrail"
  description = "Prevents disabling or deleting CloudTrail. CIS 3.1"
  type        = "SERVICE_CONTROL_POLICY"
  content     = file("${path.module}/policies/protect-cloudtrail.json")
}

resource "aws_organizations_policy_attachment" "protect_cloudtrail_root" {
  policy_id = aws_organizations_policy.protect_cloudtrail.id
  target_id = var.org_root_id
}
