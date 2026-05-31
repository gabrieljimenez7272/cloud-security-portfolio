output "guardduty_detector_id"   { value = aws_guardduty_detector.baseline.id }
output "securityhub_account_arn" { value = aws_securityhub_account.baseline.id }
output "config_recorder_name"    { value = aws_config_configuration_recorder.baseline.name }
