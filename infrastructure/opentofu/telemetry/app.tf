locals {
  app_environment = {
    PORT                          = "8080"
    MSR_BIND_HOST                 = "0.0.0.0"
    MSR_INGESTION_ENABLED         = tostring(var.ingestion_enabled)
    MSR_RESOURCE_GROUP            = azurerm_resource_group.telemetry.name
    AZURE_SUBSCRIPTION_ID         = var.subscription_id
    AZURE_TENANT_ID               = var.tenant_id
    AZURE_CLIENT_ID               = azurerm_user_assigned_identity.ingest.client_id
    AZURE_DCR_RESOURCE_ID         = azapi_resource.dcr.id
    AZURE_DCR_IMMUTABLE_ID        = azapi_resource.dcr.output.properties.immutableId
    AZURE_LOGS_ENDPOINT           = azapi_resource.dcr.output.properties.endpoints.logsIngestion
    MSR_BODY_TIMEOUT_MS           = tostring(var.limits.body_timeout_ms)
    MSR_STORAGE_TIMEOUT_MS        = tostring(var.limits.storage_timeout_ms)
    MSR_HEADERS_TIMEOUT_MS        = tostring(var.limits.headers_timeout_ms)
    MSR_MAX_CONNECTIONS           = tostring(var.limits.max_connections)
    MSR_MAX_CONCURRENT_REQUESTS   = tostring(var.limits.max_concurrent_requests)
    MSR_MAX_CONCURRENT_INGESTIONS = tostring(var.limits.max_concurrent_ingestions)
    MSR_REQUESTS_PER_MINUTE       = tostring(var.limits.requests_per_minute)
    MSR_EVENTS_PER_DAY            = tostring(var.limits.events_per_day)
  }
}

resource "azurerm_container_app" "telemetry" {
  count                        = var.deploy_app ? 1 : 0
  name                         = "${var.name_prefix}-ingest"
  resource_group_name          = azurerm_resource_group.telemetry.name
  container_app_environment_id = azurerm_container_app_environment.telemetry.id
  revision_mode                = "Single"
  max_inactive_revisions       = 3
  workload_profile_name        = "Consumption"
  tags                         = local.tags

  identity {
    type         = "UserAssigned"
    identity_ids = [azurerm_user_assigned_identity.ingest.id, azurerm_user_assigned_identity.pull.id]
  }
  registry {
    server   = azurerm_container_registry.telemetry.login_server
    identity = azurerm_user_assigned_identity.pull.id
  }
  ingress {
    external_enabled           = true
    allow_insecure_connections = false
    target_port                = 8080
    transport                  = "http"
    traffic_weight {
      latest_revision = true
      percentage      = 100
    }
  }
  template {
    min_replicas                     = var.scaling.min_replicas
    max_replicas                     = var.scaling.max_replicas
    termination_grace_period_seconds = 10
    http_scale_rule {
      name                = "bounded-http"
      concurrent_requests = var.scaling.http_concurrent_requests
    }
    container {
      name   = "telemetry-ingest"
      image  = "${azurerm_container_registry.telemetry.login_server}/missionspec/telemetry-ingest@${coalesce(var.image_digest, "UNQUALIFIED")}"
      cpu    = var.scaling.cpu
      memory = var.scaling.memory
      dynamic "env" {
        for_each = local.app_environment
        content {
          name  = env.key
          value = env.value
        }
      }
      startup_probe {
        transport               = "HTTP"
        path                    = "/health/live"
        port                    = 8080
        interval_seconds        = 1
        failure_count_threshold = 30
      }
      liveness_probe {
        transport        = "HTTP"
        path             = "/health/live"
        port             = 8080
        interval_seconds = 10
      }
      readiness_probe {
        transport               = "HTTP"
        path                    = "/health/ready"
        port                    = 8080
        interval_seconds        = 5
        failure_count_threshold = 2
        success_count_threshold = 1
      }
    }
  }
  lifecycle {
    precondition {
      condition     = var.image_digest != null
      error_message = "App deployment requires an approved immutable image digest in the new private registry."
    }
  }
  depends_on = [azurerm_role_assignment.pull, azurerm_role_assignment.ingest]
}
