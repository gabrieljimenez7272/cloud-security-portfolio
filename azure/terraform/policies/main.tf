# azure/terraform/policies/main.tf
# Azure Policy definitions enforcing security baseline.

terraform {
  required_providers {
    azurerm = {
      source  = "hashicorp/azurerm"
      version = "~> 3.0"
    }
  }
}

provider "azurerm" {
  features {}
}

# -- Require HTTPS on Storage Accounts -----------------------------------------
resource "azurerm_policy_definition" "require_https_storage" {
  name         = "require-https-storage"
  policy_type  = "Custom"
  mode         = "All"
  display_name = "Require HTTPS on Storage Accounts"
  description  = "Denies storage account creation without HTTPS-only flag. CIS 3.1"

  policy_rule = jsonencode({
    if = {
      allOf = [
        { field = "type"; equals = "Microsoft.Storage/storageAccounts" },
        { field = "Microsoft.Storage/storageAccounts/supportsHttpsTrafficOnly"; equals = "false" }
      ]
    }
    then = { effect = "Deny" }
  })
}

# -- Allowed Locations ----------------------------------------------------------
resource "azurerm_policy_definition" "allowed_locations" {
  name         = "allowed-locations"
  policy_type  = "Custom"
  mode         = "All"
  display_name = "Allowed Azure Regions"
  description  = "Restricts resource deployment to approved regions."

  policy_rule = jsonencode({
    if = {
      not = {
        field = "location"
        in    = var.allowed_locations
      }
    }
    then = { effect = "Deny" }
  })

  parameters = jsonencode({
    listOfAllowedLocations = {
      type     = "Array"
      metadata = { displayName = "Allowed locations" }
    }
  })
}
