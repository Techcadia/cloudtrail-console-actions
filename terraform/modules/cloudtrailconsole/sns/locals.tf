data "aws_caller_identity" "current" {}
data "aws_region" "current" {}

locals {
  log_group_name = coalesce(var.logs["name"], "/aws/lambda/${var.name}")
  log_group_arn  = "arn:aws:logs:${data.aws_region.current.region}:${data.aws_caller_identity.current.account_id}:log-group:${local.log_group_name}"
}
