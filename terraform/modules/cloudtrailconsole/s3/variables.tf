variable "name" {
  description = "Name of the Lambda, IAM Role and CloudWatch Log Groups"
  type        = string
  default     = "cloudTrailConsole"
}

variable "slack" {
  description = "Slack Settings"
  type        = any
  default = {
    # name    = ""
    # channel = "#aws-console-actions"
    # webhook = ""
    # accounts = {
    #   123456789012 = ":maple_leaf: NON-PRD"
    # }
  }
}

variable "s3" {
  description = "S3 Bucket Settings"
  type        = any
  default = {
    # name = ""
  }
}

variable "lambda" {
  description = "Lambda Settings"
  type        = any
  default = {
    # **Note**: Raise memory if you have slow/failed s3 loads"
    # memory                         = 256
    # timeout                        = 15
    # reserved_concurrent_executions = 10
    # environment_variables          = {}
  }
}

variable "logs" {
  description = "Log group settings"
  type = object({
    create            = optional(bool, false)
    retention_in_days = optional(number, 30)
    skip_destroy      = optional(bool, false)
    log_group_class   = optional(string, "STANDARD")
    kms_key_id        = optional(string)
  })
  default = {}
}

variable "policy" {
  description = "FilterPolicy YAML replacing the embedded default policy, e.g. file(\"policy.yaml\"). Null keeps the default. Check it first with `bootstrap --config-file policy.yaml --validate-only`."
  type        = string
  default     = null

  validation {
    condition     = var.policy == null || try(yamldecode(var.policy).kind == "FilterPolicy", false)
    error_message = "policy must be a FilterPolicy YAML document (apiVersion: cca/v1, kind: FilterPolicy)."
  }
}

variable "tags" {
  description = "A mapping of tags to supply to the resources"
  type        = map(string)
  default     = {}
}

