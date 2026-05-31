variable "subscription_id"   { type = string }
variable "allowed_locations" {
  type    = list(string)
  default = ["eastus", "westus2", "westeurope"]
}
