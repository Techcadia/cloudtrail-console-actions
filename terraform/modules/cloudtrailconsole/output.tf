output "default" {
  description = "Returns a nested map of the configured resources"
  value = {
    lambda = aws_lambda_function.default
    iam = {
      role   = aws_iam_role.default
      policy = aws_iam_role_policy.default
    }
    s3 = {
      bucket              = data.aws_s3_bucket.default
      bucket_notification = aws_s3_bucket_notification.default
    }
  }
}

output "aws_caller_identity" {
  description = "The AWS caller identity value used for grabbing account_id, current user, etc."
  value       = data.aws_caller_identity.current
}
