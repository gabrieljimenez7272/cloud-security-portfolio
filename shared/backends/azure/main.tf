# shared/backends/azure/main.tf
# Bootstraps Azure Storage remote state backend.

terraform {
  required_providers {
    azurerm = { source = "hashicorp/azurerm"; version = "~> 3.0" }
    random  = { source = "hashicorp/random";  version = "~> 3.0" }
  }
}

provider "azurerm" { features {} }

resource "random_string" "suffix" {
  length  = 6
  upper   = false
  special = false
}

resource "azurerm_resource_group" "tfstate" {
  name     = var.resource_group_name
  location = var.location
  tags     = { ManagedBy = "terraform"; Purpose = "terraform-state" }
}

resource "azurerm_storage_account" "tfstate" {
  name                            = "tfstate${random_string.suffix.result}"
  resource_group_name             = azurerm_resource_group.tfstate.name
  location                        = azurerm_resource_group.tfstate.location
  account_tier                    = "Standard"
  account_replication_type        = "GRS"
  min_tls_version                 = "TLS1_2"
  https_traffic_only_enabled      = true
  allow_nested_items_to_be_public = false

  blob_properties {
    versioning_enabled = true
    delete_retention_policy { days = 90 }
  }

  tags = { ManagedBy = "terraform"; Purpose = "terraform-state" }
}

resource "azurerm_storage_container" "tfstate" {
  name                  = "tfstate"
  storage_account_name  = azurerm_storage_account.tfstate.name
  container_access_type = "private"
}

output "storage_account_name" { value = azurerm_storage_account.tfstate.name }
output "container_name"       { value = azurerm_storage_container.tfstate.name }
output "resource_group_name"  { value = azurerm_resource_group.tfstate.name }
