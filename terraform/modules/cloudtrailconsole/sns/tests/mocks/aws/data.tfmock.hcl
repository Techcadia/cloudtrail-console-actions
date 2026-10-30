mock_data "aws_caller_identity" {
  defaults = {
    account_id = "123456789012"
    arn        = "arn:aws:iam::123456789012:user/test"
    id         = "123456789012"
    user_id    = "AIDATESTUSER"
  }
}

mock_data "aws_region" {
  defaults = {
    name   = "us-west-2"
    region = "us-west-2"
  }
}

mock_data "aws_s3_bucket" {
  defaults = {
    id     = "example-cloudtrail-bucket"
    arn    = "arn:aws:s3:::example-cloudtrail-bucket"
    bucket = "example-cloudtrail-bucket"
    region = "us-west-2"
  }
}

# The mock provider's generated ARNs fail schema validation (invalid prefix),
# so pin valid-looking ARNs for resources whose ARNs feed other resources.
mock_resource "aws_iam_role" {
  defaults = {
    arn = "arn:aws:iam::123456789012:role/cloudTrailConsole"
  }
}

mock_resource "aws_lambda_function" {
  defaults = {
    arn = "arn:aws:lambda:us-west-2:123456789012:function:cloudTrailConsole"
  }
}

mock_data "aws_iam_policy_document" {
  defaults = {
    json = "{\"Version\":\"2012-10-17\"}"
  }
}
