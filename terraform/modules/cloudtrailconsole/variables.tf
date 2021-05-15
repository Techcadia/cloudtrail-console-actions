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
    # **Note**: Raise this if you have failed s3 loads"
    # memory                         = 128
    # timeout                        = 15
    # reserved_concurrent_executions = 10
    # environment_variables          = {}
  }
}

variable "tags" {
  description = "A mapping of tags to supply to the resources"
  type        = map(string)
  default     = {}
}

