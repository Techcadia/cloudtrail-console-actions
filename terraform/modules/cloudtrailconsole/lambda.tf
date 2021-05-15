resource "aws_lambda_function" "default" {
  filename                       = lookup(var.lambda, "filepath", "${path.module}/../../../dist/function.zip")
  source_code_hash               = filebase64sha256(lookup(var.lambda, "filepath", "${path.module}/../../../dist/function.zip"))
  function_name                  = var.name
  handler                        = lookup(var.lambda, "handler", "main")
  runtime                        = lookup(var.lambda, "runtime", "go1.x")
  timeout                        = lookup(var.lambda, "timeout", 15)
  memory_size                    = lookup(var.lambda, "memory", 128)
  reserved_concurrent_executions = lookup(var.lambda, "reserved_concurrent_executions", 10)
  role                           = aws_iam_role.default.arn

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
  statement_id  = "AllowS3Invoke"
  action        = "lambda:InvokeFunction"
  function_name = aws_lambda_function.default.arn
  principal     = "s3.amazonaws.com"

  source_arn     = data.aws_s3_bucket.default.arn
  source_account = data.aws_caller_identity.current.account_id
}
