locals {
  tags        = merge(var.tags, { product = "MissionSpec", purpose = "aggregate-telemetry" })
  table_name  = "MissionSpecTelemetry_CL"
  stream_name = "Custom-MissionSpecTelemetry"
  columns     = jsondecode(file("${path.module}/../../../services/telemetry-ingest/schema/storage-columns.json"))
  schema      = jsondecode(file("${path.module}/../../../assets/schemas/telemetry-event.schema.json"))
  # Columns derive from the one canonical wire schema, not an independently maintained mapping.
  transform = "source | project ${join(", ", [for column in local.columns : column.name])}"
}

resource "azurerm_resource_group" "telemetry" {
  name     = "${var.name_prefix}-telemetry"
  location = var.location
  tags     = local.tags
}

resource "azurerm_user_assigned_identity" "ingest" {
  name                = "${var.name_prefix}-ingest"
  resource_group_name = azurerm_resource_group.telemetry.name
  location            = var.location
  tags                = local.tags
}

resource "azurerm_user_assigned_identity" "pull" {
  name                = "${var.name_prefix}-pull"
  resource_group_name = azurerm_resource_group.telemetry.name
  location            = var.location
  tags                = local.tags
}

resource "azurerm_container_registry" "telemetry" {
  name                          = var.registry_name
  resource_group_name           = azurerm_resource_group.telemetry.name
  location                      = var.location
  sku                           = "Basic"
  admin_enabled                 = false
  anonymous_pull_enabled        = false
  public_network_access_enabled = true
  tags                          = local.tags
}

resource "azurerm_role_assignment" "pull" {
  scope                = azurerm_container_registry.telemetry.id
  role_definition_name = "AcrPull"
  principal_id         = azurerm_user_assigned_identity.pull.principal_id
  principal_type       = "ServicePrincipal"
}

resource "azurerm_log_analytics_workspace" "telemetry" {
  name                            = "${var.name_prefix}-analytics"
  resource_group_name             = azurerm_resource_group.telemetry.name
  location                        = var.location
  sku                             = "PerGB2018"
  retention_in_days               = 180
  daily_quota_gb                  = var.cost_policy.workspace_daily_quota_gb
  local_authentication_enabled    = false
  internet_ingestion_access_type  = "Enabled"
  internet_query_access_type      = "Enabled"
  allow_resource_only_permissions = false
  tags                            = local.tags
}

resource "azapi_resource" "table" {
  type      = "Microsoft.OperationalInsights/workspaces/tables@2022-10-01"
  name      = local.table_name
  parent_id = azurerm_log_analytics_workspace.telemetry.id
  body = {
    properties = {
      plan                 = "Analytics"
      retentionInDays      = 180
      totalRetentionInDays = 180
      schema = {
        name    = local.table_name
        columns = local.columns
      }
    }
  }
  lifecycle {
    precondition {
      condition     = toset([for c in local.columns : c.name]) == setunion(toset(keys(local.schema.properties)), toset(["TimeGenerated"]))
      error_message = "Generate the service storage columns from the canonical schema before infrastructure validation."
    }
  }
}

resource "azapi_resource" "dcr" {
  type      = "Microsoft.Insights/dataCollectionRules@2024-03-11"
  name      = "${var.name_prefix}-dcr"
  parent_id = azurerm_resource_group.telemetry.id
  location  = var.location
  tags      = local.tags
  body = {
    kind = "Direct"
    properties = {
      streamDeclarations = { (local.stream_name) = { columns = local.columns } }
      destinations = {
        logAnalytics = [{
          name                = "missionspec"
          workspaceResourceId = azurerm_log_analytics_workspace.telemetry.id
        }]
      }
      dataFlows = [{
        streams      = [local.stream_name]
        destinations = ["missionspec"]
        outputStream = "Custom-${local.table_name}"
        transformKql = local.transform
      }]
    }
  }
  response_export_values = ["properties.immutableId", "properties.endpoints.logsIngestion"]
  depends_on             = [azapi_resource.table]
}

resource "azurerm_role_definition" "ingest" {
  name        = "${var.name_prefix}-dcr-upload-only"
  scope       = azurerm_resource_group.telemetry.id
  description = "Only upload to MissionSpec's intended DCR; no query or control-plane permissions."
  permissions {
    actions      = []
    data_actions = ["Microsoft.Insights/Telemetry/Write"]
  }
  assignable_scopes = [azurerm_resource_group.telemetry.id]
}

resource "azurerm_role_assignment" "ingest" {
  scope              = azapi_resource.dcr.id
  role_definition_id = azurerm_role_definition.ingest.role_definition_resource_id
  principal_id       = azurerm_user_assigned_identity.ingest.principal_id
  principal_type     = "ServicePrincipal"
}

resource "azurerm_role_assignment" "query" {
  for_each             = var.query_principal_ids
  scope                = azurerm_log_analytics_workspace.telemetry.id
  role_definition_name = "Log Analytics Reader"
  principal_id         = each.value
}

resource "azurerm_container_app_environment" "telemetry" {
  name                  = "${var.name_prefix}-environment"
  resource_group_name   = azurerm_resource_group.telemetry.name
  location              = var.location
  public_network_access = "Enabled"
  # Omitted log destination disables persistence. No diagnostic settings, Dapr, or App Insights.
  logs_destination = null
  workload_profile {
    name                  = "Consumption"
    workload_profile_type = "Consumption"
  }
  tags = local.tags
}

resource "azurerm_consumption_budget_resource_group" "telemetry" {
  name              = "${var.name_prefix}-budget"
  resource_group_id = azurerm_resource_group.telemetry.id
  amount            = var.cost_policy.monthly_budget
  time_grain        = "Monthly"
  time_period {
    start_date = var.cost_policy.budget_start_date
    end_date   = var.cost_policy.budget_end_date
  }
  notification {
    enabled        = true
    threshold      = 80
    operator       = "GreaterThanOrEqualTo"
    threshold_type = "Actual"
    contact_emails = var.cost_policy.notification_emails
  }
  notification {
    enabled        = true
    threshold      = 100
    operator       = "GreaterThanOrEqualTo"
    threshold_type = "Forecasted"
    contact_emails = var.cost_policy.notification_emails
  }
}
