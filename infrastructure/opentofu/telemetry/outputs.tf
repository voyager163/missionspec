output "candidate_endpoint" {
  description = "Unqualified candidate only. Not authorization to contact or compile into the CLI."
  value       = var.deploy_app ? "https://${azurerm_container_app.telemetry[0].ingress[0].fqdn}/v1/events" : null
}

output "registry_login_server" {
  value = azurerm_container_registry.telemetry.login_server
}

output "workspace_id" {
  value = azurerm_log_analytics_workspace.telemetry.id
}

output "dcr_id" {
  value = azapi_resource.dcr.id
}

output "retention_policy" {
  value = {
    analytics_days = 180
    total_days     = 180
    extra_archive  = false
    export         = false
  }
}
