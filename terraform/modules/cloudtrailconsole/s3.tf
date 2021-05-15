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
  }

  depends_on = [
    aws_lambda_permission.default
  ]
}
