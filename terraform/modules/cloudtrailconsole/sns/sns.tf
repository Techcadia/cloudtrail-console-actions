resource "aws_sns_topic_subscription" "default" {
  for_each  = var.sns
  topic_arn = lookup(each.value, "topic_arn", null)
  protocol  = lookup(each.value, "protocol", "lambda")
  endpoint  = lookup(each.value, "endpoint", aws_lambda_function.default.arn)

  depends_on = [
    aws_lambda_permission.default
  ]
}
