# shared/modules/tagging/main.tf
# Enforces the org tagging standard on any resource that calls this module.

variable "environment"  { type = string }
variable "owner"        { type = string }
variable "cost_center"  { type = string }
variable "data_class"   { type = string }
variable "project"      { type = string; default = "" }
variable "extra_tags"   { type = map(string); default = {} }

locals {
  required_tags = {
    Environment = var.environment
    Owner       = var.owner
    CostCenter  = var.cost_center
    DataClass   = var.data_class
    ManagedBy   = "terraform"
    Project     = var.project
  }
  all_tags = merge(local.required_tags, var.extra_tags)
}

output "tags" {
  value = local.all_tags
}
