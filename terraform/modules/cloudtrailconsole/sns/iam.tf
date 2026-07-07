data "aws_iam_policy_document" "sts" {
  statement {
    actions = ["sts:AssumeRole"]

    principals {
      identifiers = [
        "lambda.amazonaws.com",
      ]
      type = "Service"
    }
  }
}

resource "aws_iam_role" "default" {
  name               = var.name
  assume_role_policy = data.aws_iam_policy_document.sts.json

  tags = merge(
    var.tags,
    {
      "Name" = var.name
    }
  )
}

data "aws_iam_policy_document" "default" {
  # The log group itself is created by aws_cloudwatch_log_group.default (with a
  # managed retention), so the role only needs to write streams — not create
  # the group.
  statement {
    actions = [
      "logs:CreateLogStream",
      "logs:PutLogEvents",
    ]
    resources = [
      "${aws_cloudwatch_log_group.default.arn}:*",
    ]
  }

  statement {
    actions = [
      "s3:GetObject",
    ]
    resources = [
      "${data.aws_s3_bucket.default.arn}/*"
    ]
  }

}

resource "aws_iam_role_policy" "default" {
  name   = var.name
  role   = aws_iam_role.default.id
  policy = data.aws_iam_policy_document.default.json
}
