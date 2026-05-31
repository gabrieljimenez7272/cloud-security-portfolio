# Azure Terraform Remote State Backend

Uses Azure Storage Account + blob container for state, with storage account key
or managed identity auth.

## Bootstrap (run once)

```bash
cd shared/backends/azure
terraform init
terraform apply -var="resource_group_name=rg-terraform-state" -var="location=eastus"
```

## Usage in provider modules

```hcl
terraform {
  backend "azurerm" {
    resource_group_name  = "rg-terraform-state"
    storage_account_name = "tfstate<unique_suffix>"
    container_name       = "tfstate"
    key                  = "azure/policies/terraform.tfstate"
  }
}
```
