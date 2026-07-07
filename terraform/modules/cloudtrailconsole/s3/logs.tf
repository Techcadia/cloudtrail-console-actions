# Own the Lambda's log group in Terraform so retention is bounded (an
# auto-created group never expires) and the role doesn't need logs:CreateLogGroup.
resource "aws_cloudwatch_log_group" "default" {
  name              = "/aws/lambda/${var.name}"
  retention_in_days = lookup(var.lambda, "log_retention_in_days", 90)

  tags = merge(
    var.tags,
    {
      "Name" = var.name
    }
  )
}
