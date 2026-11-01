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
  # Lambda creates its own log group on first write unless logs.create manages
  # it in Terraform; the role needs CreateLogGroup either way so a deleted
  # group can be recreated.
  statement {
    actions = [
      "logs:CreateLogGroup",
    ]
    resources = [
      local.log_group_arn,
    ]
  }

  statement {
    actions = [
      "logs:CreateLogStream",
      "logs:PutLogEvents",
    ]
    resources = [
      "${local.log_group_arn}:log-stream:*",
    ]
  }

  statement {
    actions = [
      "s3:ListBucket"
    ]
    resources = [
      data.aws_s3_bucket.default.arn
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
