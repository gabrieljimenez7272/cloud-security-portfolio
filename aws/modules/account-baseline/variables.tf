variable "account_name"        { type = string; description = "Human-readable account name" }
variable "environment"         { type = string; description = "prod | staging | dev" }
variable "security_account_id" { type = string; description = "Central security/audit account ID" }
variable "log_archive_bucket"  { type = string; description = "Central S3 bucket for CloudTrail/Config logs" }
variable "home_region"         { type = string; default = "us-east-1" }
