variable "subscription_id" {
  type        = string
  description = "MissionSpec-owned public Azure subscription; no inherited product resources."
  validation {
    condition     = can(regex("^[0-9a-fA-F-]{36}$", var.subscription_id))
    error_message = "Supply an explicit subscription UUID."
  }
}

variable "tenant_id" {
  type        = string
  description = "Operator-selected Entra tenant UUID."
}

variable "deployment_client_id" {
  type        = string
  description = "Approved federated deployment principal client UUID; not a secret."
}

variable "location" {
  type        = string
  description = "Explicit Azure public-cloud region after residency/capacity review."
  validation {
    condition     = can(regex("^[a-z0-9]+$", var.location))
    error_message = "Use an explicit canonical Azure region name."
  }
}

variable "name_prefix" {
  type        = string
  description = "Unique MissionSpec resource identity, e.g. missionspec-<operator suffix>."
  validation {
    condition     = can(regex("^missionspec-[a-z0-9]{2,10}$", var.name_prefix))
    error_message = "Use missionspec- followed by 2–10 lowercase letters/digits."
  }
}

variable "registry_name" {
  type        = string
  description = "Globally unique MissionSpec-only ACR name."
  validation {
    condition     = can(regex("^missionspec[a-z0-9]{2,35}$", var.registry_name))
    error_message = "Use missionspec followed by 2–35 lowercase letters/digits."
  }
}

variable "deploy_app" {
  type        = bool
  description = "False for registry/data-plane bootstrap; true only after separately authorized immutable image publication."
}

variable "image_digest" {
  type        = string
  default     = null
  nullable    = true
  description = "Approved manifest sha256 digest already present in this deployment's private ACR."
  validation {
    condition     = var.image_digest == null ? true : can(regex("^sha256:[0-9a-f]{64}$", var.image_digest))
    error_message = "An immutable sha256 image digest is required; tags are forbidden."
  }
}

variable "ingestion_enabled" {
  type        = bool
  default     = false
  description = "Emergency kill switch. Enable only at the separately authorized synthetic qualification gate."
}

variable "endpoint_domain_policy" {
  type        = string
  description = "Explicit initial hostname decision. Custom domains need a separately reviewed DNS/TLS binding extension."
  validation {
    condition     = var.endpoint_domain_policy == "azure-managed"
    error_message = "This module supports only an explicitly selected Azure-managed TLS hostname; custom DNS is not provisioned."
  }
}

variable "query_principal_ids" {
  type        = set(string)
  description = "Nonempty approved Entra operator/group object UUIDs granted query access only to the dedicated workspace."
  validation {
    condition     = length(var.query_principal_ids) > 0 && alltrue([for id in var.query_principal_ids : can(regex("^[0-9a-fA-F-]{36}$", id))])
    error_message = "At least one explicit query operator/group UUID is required."
  }
}

variable "scaling" {
  type = object({
    min_replicas             = number
    max_replicas             = number
    cpu                      = number
    memory                   = string
    http_concurrent_requests = number
  })
  description = "Reviewed bounded Consumption capacity. Singleton max is required until a distributed quota exists."
  validation {
    condition = (
      contains([0, 1], var.scaling.min_replicas) && var.scaling.max_replicas == 1 &&
      contains(["0.25/0.5Gi", "0.5/1Gi", "1/2Gi"], "${var.scaling.cpu}/${var.scaling.memory}") &&
      var.scaling.http_concurrent_requests >= 1 && var.scaling.http_concurrent_requests <= 256 &&
      floor(var.scaling.http_concurrent_requests) == var.scaling.http_concurrent_requests
    )
    error_message = "Choose 0/1 minimum, singleton maximum, a supported bounded CPU/memory pair, and 1–256 HTTP concurrency."
  }
}

variable "limits" {
  type = object({
    body_timeout_ms           = number
    storage_timeout_ms        = number
    headers_timeout_ms        = number
    max_connections           = number
    max_concurrent_requests   = number
    max_concurrent_ingestions = number
    requests_per_minute       = number
    events_per_day            = number
  })
  description = "Explicit all-client in-memory request/work/attempt quotas; process restarts reset quotas."
  validation {
    condition = (
      alltrue([for v in values(var.limits) : v == floor(v) && v >= 1]) &&
      var.limits.body_timeout_ms >= 10 && var.limits.body_timeout_ms <= 5000 &&
      var.limits.storage_timeout_ms >= 10 && var.limits.storage_timeout_ms <= 5000 &&
      var.limits.headers_timeout_ms >= 10 && var.limits.headers_timeout_ms <= 5000 &&
      var.limits.max_connections <= 1024 && var.limits.max_concurrent_requests <= 256 &&
      var.limits.max_concurrent_ingestions <= 64 &&
      var.limits.max_concurrent_ingestions <= var.limits.max_concurrent_requests &&
      var.limits.max_concurrent_requests <= var.limits.max_connections &&
      var.limits.requests_per_minute <= 60000 && var.limits.events_per_day <= 1000000
    )
    error_message = "Service limits must be integral, positive, bounded, and internally consistent."
  }
}

variable "cost_policy" {
  type = object({
    reviewed                 = bool
    workspace_daily_quota_gb = number
    monthly_budget           = number
    budget_start_date        = string
    budget_end_date          = string
    notification_emails      = set(string)
  })
  description = "Approved cost policy in subscription billing currency. Budgets and workspace caps are not hard spend ceilings."
  validation {
    condition = (
      var.cost_policy.reviewed && var.cost_policy.workspace_daily_quota_gb > 0 &&
      var.cost_policy.workspace_daily_quota_gb <= 10 &&
      var.cost_policy.monthly_budget > 0 && length(var.cost_policy.notification_emails) > 0 &&
      can(regex("^[0-9]{4}-[0-9]{2}-01T00:00:00Z$", var.cost_policy.budget_start_date)) &&
      can(regex("^[0-9]{4}-[0-9]{2}-01T00:00:00Z$", var.cost_policy.budget_end_date))
    )
    error_message = "Explicit reviewed quota, positive budget, first-of-month UTC dates, and budget contacts are required."
  }
}

variable "tags" {
  type        = map(string)
  default     = {}
  description = "Operator metadata only; never secrets or event fields."
}
