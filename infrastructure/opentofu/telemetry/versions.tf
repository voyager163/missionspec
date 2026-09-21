terraform {
  required_version = ">= 1.12.0, < 2.0.0"

  required_providers {
    azurerm = {
      source  = "hashicorp/azurerm"
      version = "= 5.6.0"
    }
    azapi = {
      source  = "Azure/azapi"
      version = "= 2.12.0"
    }
  }

  # Operator-owned private storage must already exist. Never fall back to local state.
  backend "azurerm" {
    use_azuread_auth = true
  }
}

provider "azurerm" {
  features {}
  subscription_id                 = var.subscription_id
  tenant_id                       = var.tenant_id
  client_id                       = var.deployment_client_id
  environment                     = "public"
  use_oidc                        = true
  use_cli                         = false
  resource_provider_registrations = "none"
}

provider "azapi" {
  subscription_id            = var.subscription_id
  tenant_id                  = var.tenant_id
  client_id                  = var.deployment_client_id
  environment                = "public"
  use_oidc                   = true
  use_cli                    = false
  skip_provider_registration = true
  enable_preflight           = false
  disable_default_output     = true
}
