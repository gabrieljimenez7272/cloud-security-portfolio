# aws/terraform/iam/main.tf
# Least-privilege IAM roles with permission boundaries.

terraform {
  required_providers {
    aws = { source = "hashicorp/aws"; version = "~> 5.0" }
  }
}

# -- Permission Boundary --------------------------------------------------------
# Applied to all developer/operator roles to cap maximum permissions.
resource "aws_iam_policy" "developer_boundary" {
  name        = "DeveloperPermissionBoundary"
  description = "Permission boundary capping developer roles"
  policy      = file("${path.module}/policies/developer-boundary.json")
}

# -- Read-Only Auditor Role -----------------------------------------------------
resource "aws_iam_role" "security_auditor" {
  name               = "SecurityAuditor"
  assume_role_policy = data.aws_iam_policy_document.assume_role_policy.json
  tags = {
    ManagedBy   = "terraform"
    Environment = var.environment
  }
}

resource "aws_iam_role_policy_attachment" "auditor_readonly" {
  role       = aws_iam_role.security_auditor.name
  policy_arn = "arn:aws:iam::aws:policy/SecurityAudit"
}

data "aws_iam_policy_document" "assume_role_policy" {
  statement {
    actions = ["sts:AssumeRole"]
    principals {
      type        = "AWS"
      identifiers = [var.trusted_account_id]
    }
    condition {
      test     = "Bool"
      variable = "aws:MultiFactorAuthPresent"
      values   = ["true"]
    }
  }
}
