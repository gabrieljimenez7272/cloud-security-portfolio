# entra-id/terraform/apps/main.tf
# App registrations for internal tooling.

terraform {
  required_providers {
    azuread = {
      source  = "hashicorp/azuread"
      version = "~> 2.0"
    }
  }
}

# -- Security Automation Service Principal --------------------------------------
resource "azuread_application" "security_automation" {
  display_name = "security-automation-sp"
  owners       = [data.azuread_client_config.current.object_id]

  required_resource_access {
    resource_app_id = "00000003-0000-0000-c000-000000000000" # Microsoft Graph

    resource_access {
      id   = "246dd0d5-5bd0-4def-940b-0421030a5b68" # Policy.Read.All
      type = "Role"
    }
    resource_access {
      id   = "bf394140-e372-4bf9-a898-299cfc7564e5" # SecurityEvents.Read.All
      type = "Role"
    }
  }
}

resource "azuread_service_principal" "security_automation" {
  client_id = azuread_application.security_automation.client_id
  owners    = [data.azuread_client_config.current.object_id]
}

data "azuread_client_config" "current" {}
