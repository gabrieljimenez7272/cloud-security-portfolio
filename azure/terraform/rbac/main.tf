# azure/terraform/rbac/main.tf
# Custom RBAC roles for least-privilege access patterns.

# -- Security Reader (read-only, no data plane) ---------------------------------
resource "azurerm_role_definition" "security_reader" {
  name        = "Custom Security Reader"
  scope       = data.azurerm_subscription.current.id
  description = "Read access to security configs; no data plane access."

  permissions {
    actions = [
      "Microsoft.Security/*/read",
      "Microsoft.Authorization/*/read",
      "Microsoft.Insights/alertRules/read",
      "Microsoft.PolicyInsights/*/read",
    ]
    not_actions = []
  }

  assignable_scopes = [data.azurerm_subscription.current.id]
}

data "azurerm_subscription" "current" {}
