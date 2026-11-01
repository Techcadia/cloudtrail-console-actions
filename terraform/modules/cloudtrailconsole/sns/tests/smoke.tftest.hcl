# Every run sets values explicitly and asserts against those literals, never
# against module defaults, so changing a default does not break these tests.
mock_provider "aws" {
  source = "./tests/mocks/aws"
}

variables {
  name = "testConsole"

  s3 = {
    name = "example-cloudtrail-bucket"
  }

  # Committed fixture; the module's default dist/function.zip is a build artifact.
  lambda = {
    filepath                       = "./tests/fixtures/function.zip"
    handler                        = "bootstrap"
    runtime                        = "provided.al2"
    memory                         = 256
    timeout                        = 60
    reserved_concurrent_executions = 5
    architectures                  = ["x86_64"]
    environment_variables = {
      LOG_LEVEL = "DEBUG"
    }
  }

  sns = {
    cloudtrail = {
      topic_arn = "arn:aws:sns:us-west-2:123456789012:cloudtrail-console"
    }
  }
}

run "lambda_settings" {
  command = apply

  assert {
    condition     = aws_lambda_function.default.function_name == "testConsole"
    error_message = "Lambda should use the provided name"
  }

  assert {
    condition     = aws_iam_role.default.name == "testConsole"
    error_message = "IAM role should use the provided name"
  }

  assert {
    condition     = aws_lambda_function.default.handler == "bootstrap" && aws_lambda_function.default.runtime == "provided.al2"
    error_message = "Lambda should use the provided handler and runtime"
  }

  assert {
    condition     = aws_lambda_function.default.memory_size == 256 && aws_lambda_function.default.timeout == 60
    error_message = "Lambda should use the provided memory and timeout"
  }

  assert {
    condition     = aws_lambda_function.default.reserved_concurrent_executions == 5
    error_message = "Lambda should use the provided reserved concurrency"
  }

  assert {
    condition     = aws_lambda_function.default.architectures == tolist(["x86_64"])
    error_message = "Lambda should use the provided architectures"
  }

  assert {
    condition     = aws_lambda_function.default.environment[0].variables["LOG_LEVEL"] == "DEBUG"
    error_message = "Lambda should include the provided environment variables"
  }
}

run "topic_wiring" {
  command = apply

  assert {
    condition     = length(aws_sns_topic_subscription.default) == 1
    error_message = "One SNS subscription should be created for the provided topic"
  }

  assert {
    condition     = aws_sns_topic_subscription.default["cloudtrail"].topic_arn == "arn:aws:sns:us-west-2:123456789012:cloudtrail-console"
    error_message = "Subscription should target the provided topic ARN"
  }

  assert {
    condition     = aws_sns_topic_subscription.default["cloudtrail"].endpoint == aws_lambda_function.default.arn
    error_message = "Subscription endpoint should be the module Lambda"
  }

  assert {
    condition     = aws_lambda_permission.default["cloudtrail"].principal == "sns.amazonaws.com"
    error_message = "Lambda permission should allow invocation from SNS"
  }

  assert {
    condition     = aws_lambda_permission.default["cloudtrail"].source_arn == "arn:aws:sns:us-west-2:123456789012:cloudtrail-console"
    error_message = "Lambda permission source ARN should be the topic ARN"
  }

  assert {
    condition     = output.aws_caller_identity.account_id == "123456789012"
    error_message = "Caller identity output should pass through the mocked account id"
  }
}

run "subscription_overrides" {
  command = apply

  variables {
    sns = {
      cloudtrail = {
        topic_arn = "arn:aws:sns:us-west-2:123456789012:cloudtrail-console"
        protocol  = "https"
        endpoint  = "https://example.com/hook"
      }
    }
  }

  assert {
    condition     = aws_sns_topic_subscription.default["cloudtrail"].protocol == "https"
    error_message = "Subscription should use the provided protocol"
  }

  assert {
    condition     = aws_sns_topic_subscription.default["cloudtrail"].endpoint == "https://example.com/hook"
    error_message = "Subscription should use the provided endpoint"
  }
}

run "multiple_topics_and_custom_permission" {
  command = apply

  variables {
    sns = {
      non_prd = {
        topic_arn = "arn:aws:sns:us-west-2:123456789012:cloudtrail-console-non-prd"
      }
      prd = {
        topic_arn = "arn:aws:sns:us-west-2:123456789012:cloudtrail-console-prd"
      }
    }
    lambda = {
      filepath = "./tests/fixtures/function.zip"
      permissions = {
        eventbridge = {
          statement_id = "AllowExecutionFromEventBridge"
          principal    = "events.amazonaws.com"
          source_arn   = "arn:aws:events:us-west-2:123456789012:rule/example-rule"
        }
      }
    }
  }

  assert {
    condition     = length(aws_sns_topic_subscription.default) == 2
    error_message = "One subscription should be created per provided topic"
  }

  assert {
    condition     = length(aws_lambda_permission.default) == 3
    error_message = "Lambda permissions should include both SNS topics and the custom permission"
  }

  assert {
    condition     = aws_lambda_permission.default["eventbridge"].statement_id == "AllowExecutionFromEventBridge"
    error_message = "Custom permission should use the provided statement id"
  }

  assert {
    condition     = aws_lambda_permission.default["eventbridge"].principal == "events.amazonaws.com"
    error_message = "Custom permission should use the provided principal"
  }
}

run "log_group_settings" {
  command = apply

  variables {
    logs = {
      create            = true
      retention_in_days = 90
      skip_destroy      = true
      log_group_class   = "INFREQUENT_ACCESS"
      kms_key_id        = "arn:aws:kms:us-west-2:123456789012:key/12345678-1234-1234-1234-123456789012"
    }
  }

  assert {
    condition     = length(aws_cloudwatch_log_group.default) == 1
    error_message = "Log group should be created when explicitly requested"
  }

  assert {
    condition     = aws_cloudwatch_log_group.default[0].name == "/aws/lambda/testConsole"
    error_message = "Log group name should follow the provided name"
  }

  assert {
    condition     = aws_cloudwatch_log_group.default[0].retention_in_days == 90
    error_message = "Log group should use the provided retention"
  }

  assert {
    condition     = aws_cloudwatch_log_group.default[0].skip_destroy == true
    error_message = "Log group should use the provided skip_destroy"
  }

  assert {
    condition     = aws_cloudwatch_log_group.default[0].log_group_class == "INFREQUENT_ACCESS"
    error_message = "Log group should use the provided log group class"
  }

  assert {
    condition     = aws_cloudwatch_log_group.default[0].kms_key_id == "arn:aws:kms:us-west-2:123456789012:key/12345678-1234-1234-1234-123456789012"
    error_message = "Log group should use the provided KMS key"
  }
}

run "log_group_custom_name" {
  command = apply

  variables {
    logs = {
      create = true
      name   = "/custom/log-group"
    }
  }

  assert {
    condition     = aws_cloudwatch_log_group.default[0].name == "/custom/log-group"
    error_message = "Log group should use the provided name over the derived one"
  }
}

run "log_group_disabled" {
  command = apply

  variables {
    logs = {
      create = false
    }
  }

  assert {
    condition     = length(aws_cloudwatch_log_group.default) == 0
    error_message = "Log group should not be created when create = false"
  }
}

run "custom_name_and_tags" {
  command = apply

  variables {
    name = "myConsoleLogger"
    logs = {
      create = true
    }
    tags = {
      Environment = "non-prd"
      ManagedBy   = "terraform"
    }
  }

  assert {
    condition     = aws_lambda_function.default.function_name == "myConsoleLogger"
    error_message = "Lambda should use the provided name"
  }

  assert {
    condition     = aws_iam_role.default.name == "myConsoleLogger"
    error_message = "IAM role should use the provided name"
  }

  assert {
    condition     = aws_cloudwatch_log_group.default[0].name == "/aws/lambda/myConsoleLogger"
    error_message = "Log group name should follow the provided name"
  }

  assert {
    condition     = aws_lambda_function.default.tags["Environment"] == "non-prd" && aws_lambda_function.default.tags["Name"] == "myConsoleLogger"
    error_message = "Lambda tags should merge provided tags with the Name tag"
  }
}

run "slack_settings" {
  command = apply

  variables {
    slack = {
      name    = ":maple_leaf: NON-PRD"
      channel = "#aws-console-actions"
      webhook = "https://hooks.slack.com/services/T00000000/B00000000/XXXXXXXXXXXXXXXXXXXXXXXX"
      accounts = {
        "123456789012" = ":maple_leaf: NON-PRD"
        "210987654321" = ":evergreen_tree: PRD"
      }
    }
  }

  assert {
    condition     = aws_lambda_function.default.environment[0].variables["SLACK_NAME"] == ":maple_leaf: NON-PRD"
    error_message = "Lambda environment should include SLACK_NAME"
  }

  assert {
    condition     = aws_lambda_function.default.environment[0].variables["SLACK_CHANNEL"] == "#aws-console-actions"
    error_message = "Lambda environment should include SLACK_CHANNEL"
  }

  assert {
    condition     = aws_lambda_function.default.environment[0].variables["SLACK_WEBHOOK"] == "https://hooks.slack.com/services/T00000000/B00000000/XXXXXXXXXXXXXXXXXXXXXXXX"
    error_message = "Lambda environment should include SLACK_WEBHOOK"
  }

  assert {
    condition     = aws_lambda_function.default.environment[0].variables["SLACK_NAME_123456789012"] == ":maple_leaf: NON-PRD"
    error_message = "Lambda environment should include per-account SLACK_NAME_<account_id>"
  }

  assert {
    condition     = aws_lambda_function.default.environment[0].variables["SLACK_NAME_210987654321"] == ":evergreen_tree: PRD"
    error_message = "Lambda environment should include per-account SLACK_NAME_<account_id>"
  }

  assert {
    condition     = aws_lambda_function.default.environment[0].variables["LOG_LEVEL"] == "DEBUG"
    error_message = "Slack settings should merge with the provided environment variables"
  }
}
