data "aws_s3_bucket" "default" {
  bucket = var.s3["name"]
}

resource "aws_s3_bucket_notification" "default" {
  bucket = data.aws_s3_bucket.default.id

  lambda_function {
    lambda_function_arn = aws_lambda_function.default.arn
    events = [
      "s3:ObjectCreated:*"
    ]
    # CloudTrail log objects are gzipped JSON; the suffix filter keeps
    # unrelated uploads from invoking (and failing) the Lambda.
    filter_suffix = ".json.gz"
  }

  depends_on = [
    aws_lambda_permission.default
  ]
}
