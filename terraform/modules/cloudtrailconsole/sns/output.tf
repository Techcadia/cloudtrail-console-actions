output "default" {
  description = "Returns a nested map of the configured resources"
  value = {
    lambda = aws_lambda_function.default
    iam = {
      role = merge(
        aws_iam_role.default,
        {
          // Filter out things that are not useful
          assume_role_policy = null,
          inline_policy      = null
        }
      )
      policy = merge(
        aws_iam_role_policy.default,
        {
          // Filter out things that are not useful
          policy = null
        }
      )
    }
    s3 = {
      bucket = data.aws_s3_bucket.default
    }
  }
}

output "aws_caller_identity" {
  description = "The AWS caller identity value used for grabbing account_id, current user, etc."
  value       = data.aws_caller_identity.current
}
