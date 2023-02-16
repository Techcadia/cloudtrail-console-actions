resource "aws_lambda_function" "default" {
  filename                       = lookup(var.lambda, "filepath", "${path.module}/../../../../dist/function.zip")
  source_code_hash               = filebase64sha256(lookup(var.lambda, "filepath", "${path.module}/../../../../dist/function.zip"))
  function_name                  = var.name
  handler                        = lookup(var.lambda, "handler", "main")
  runtime                        = lookup(var.lambda, "runtime", "go1.x")
  timeout                        = lookup(var.lambda, "timeout", 15)
  memory_size                    = lookup(var.lambda, "memory", 128)
  reserved_concurrent_executions = lookup(var.lambda, "reserved_concurrent_executions", 10)
  role                           = aws_iam_role.default.arn
  architectures                  = lookup(var.lambda, "architectures", ["x86_64"])

  environment {
    variables = merge(
      { for k, v in lookup(var.slack, "accounts", {}) : "SLACK_NAME_${k}" => v },
      lookup(var.slack, "name", null) != null ? { "SLACK_NAME" = var.slack["name"] } : {},
      lookup(var.slack, "webhook", null) != null ? { "SLACK_WEBHOOK" = var.slack["webhook"] } : {},
      lookup(var.slack, "channel", null) != null ? { "SLACK_CHANNEL" = var.slack["channel"] } : {},
      { for k, v in lookup(var.lambda, "environment_variables", {}) : k => v },
    )
  }

  tags = merge(
    var.tags,
    {
      "Name" = var.name
    }
  )
}

resource "aws_lambda_permission" "default" {
  for_each = merge(
    { for k, v in var.sns : k => merge({ source_arn = v["topic_arn"] }, v) },
    { for k, v in lookup(var.lambda, "permissions", {}) : k => v }
  )

  # for_each = merge({
  #   for k, v in lookup(var.lambda, "triggers", {}) : k => merge({
  #     statement_id = "AllowExecutionFromSNS",
  #     principal    = "sns.amazonaws.com",
  #     source_arn   = lookup(v, "topic_arn", null)
  #   }, v)
  #   if v.type == "sns_topic"
  #   },
  #   {
  #     for k, v in lookup(var.lambda, "triggers", {}) : k => v
  #     if v.type == "s3_bucket_notification"
  # })

  statement_id   = lookup(each.value, "statement_id", "AllowExecutionFromSNS")
  action         = lookup(each.value, "action", "lambda:InvokeFunction")
  function_name  = lookup(each.value, "function_name", aws_lambda_function.default.arn)
  principal      = lookup(each.value, "principal", "sns.amazonaws.com")
  source_arn     = lookup(each.value, "source_arn", null)
  source_account = lookup(each.value, "source_account", data.aws_caller_identity.current.account_id)
}
