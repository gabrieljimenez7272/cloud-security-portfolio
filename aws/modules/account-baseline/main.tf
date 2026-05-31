# aws/modules/account-baseline/main.tf
# Applied to every AWS account as a security baseline.

terraform {
  required_providers {
    aws = { source = "hashicorp/aws"; version = "~> 5.0" }
  }
}

data "aws_caller_identity" "current" {}
data "aws_regions" "available" { all_regions = false }

# -- IAM Account Password Policy (CIS 1.8-1.11) --------------------------------
resource "aws_iam_account_password_policy" "cis_baseline" {
  minimum_password_length        = 14
  require_uppercase_characters   = true
  require_lowercase_characters   = true
  require_numbers                = true
  require_symbols                = true
  allow_users_to_change_password = true
  max_password_age               = 90
  password_reuse_prevention      = 24
  hard_expiry                    = false
}

# -- S3 Account-Level Public Access Block (CIS 2.1.5) --------------------------
resource "aws_s3_account_public_access_block" "baseline" {
  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

# -- EBS Default Encryption (CIS 2.2.1) ----------------------------------------
resource "aws_ebs_encryption_by_default" "baseline" {
  enabled = true
}

# -- Security Hub (CIS + FSBP standards) ----------------------------------------
resource "aws_securityhub_account" "baseline" {}

resource "aws_securityhub_standards_subscription" "cis_v3" {
  depends_on    = [aws_securityhub_account.baseline]
  standards_arn = "arn:aws:securityhub:${var.home_region}::standards/cis-aws-foundations-benchmark/v/3.0.0"
}

resource "aws_securityhub_standards_subscription" "fsbp" {
  depends_on    = [aws_securityhub_account.baseline]
  standards_arn = "arn:aws:securityhub:${var.home_region}::standards/aws-foundational-security-best-practices/v/1.0.0"
}

# -- GuardDuty (delegated to security account) ---------------------------------
resource "aws_guardduty_detector" "baseline" {
  enable = true

  datasources {
    s3_logs               { enable = true }
    kubernetes { audit_logs { enable = true } }
    malware_protection {
      scan_ec2_instance_with_findings { ebs_volumes { enable = true } }
    }
  }
}

# -- AWS Config -----------------------------------------------------------------
resource "aws_config_configuration_recorder" "baseline" {
  name     = "baseline-recorder"
  role_arn = aws_iam_role.config_role.arn

  recording_group {
    all_supported                 = true
    include_global_resource_types = true
  }
}

resource "aws_config_delivery_channel" "baseline" {
  name           = "baseline-channel"
  s3_bucket_name = var.log_archive_bucket
  depends_on     = [aws_config_configuration_recorder.baseline]
}

resource "aws_config_configuration_recorder_status" "baseline" {
  name       = aws_config_configuration_recorder.baseline.name
  is_enabled = true
  depends_on = [aws_config_delivery_channel.baseline]
}

resource "aws_iam_role" "config_role" {
  name               = "AWSConfigRole"
  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Action    = "sts:AssumeRole"
      Effect    = "Allow"
      Principal = { Service = "config.amazonaws.com" }
    }]
  })
}

resource "aws_iam_role_policy_attachment" "config_policy" {
  role       = aws_iam_role.config_role.name
  policy_arn = "arn:aws:iam::aws:policy/service-role/AWS_ConfigRole"
}

# -- Delete Default VPCs in all active regions ----------------------------------
# NOTE: Uses null_resource + local-exec. Requires AWS CLI configured.
resource "null_resource" "delete_default_vpcs" {
  provisioner "local-exec" {
    command = <<-EOT
      for region in $(aws ec2 describe-regions --query 'Regions[].RegionName' --output text); do
        vpc_id=$(aws ec2 describe-vpcs --region $region           --filters Name=isDefault,Values=true           --query 'Vpcs[0].VpcId' --output text 2>/dev/null)
        if [ "$vpc_id" != "None" ] && [ -n "$vpc_id" ]; then
          echo "Deleting default VPC $vpc_id in $region"
          # Delete IGW
          igw=$(aws ec2 describe-internet-gateways --region $region             --filters "Name=attachment.vpc-id,Values=$vpc_id"             --query 'InternetGateways[0].InternetGatewayId' --output text)
          [ "$igw" != "None" ] && aws ec2 detach-internet-gateway --region $region             --internet-gateway-id $igw --vpc-id $vpc_id &&             aws ec2 delete-internet-gateway --region $region --internet-gateway-id $igw
          # Delete subnets
          for subnet in $(aws ec2 describe-subnets --region $region             --filters "Name=vpc-id,Values=$vpc_id"             --query 'Subnets[].SubnetId' --output text); do
            aws ec2 delete-subnet --region $region --subnet-id $subnet
          done
          aws ec2 delete-vpc --region $region --vpc-id $vpc_id
          echo "  Done."
        fi
      done
    EOT
  }

  triggers = { account_id = data.aws_caller_identity.current.account_id }
}
