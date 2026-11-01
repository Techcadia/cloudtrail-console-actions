module "default" {
  source = "../modules/cloudtrailconsole/sns"
  name   = "cloudTrailConsole"

  s3 = {
    name = "example-com-non-prd-cloudtrail"
  }

  sns = {
    sns_topic = {
      topic_arn = "arn:aws:sns:us-east-1:123456789012:CloudTrail"
    }
  }

  lambda = {
    # **Note**: Increase memory if you are experiencing slow s3 reads"
    memory                         = 256
    timeout                        = 15
    reserved_concurrent_executions = 10
    environment_variables          = {}
    # **Note**: Depending on your Terraform directory structure you might need to define the filepath.
    filepath = "../../../cloudtrail-console-actions/dist/function_arm64.zip"
  }

  # Manage the Lambda log group (and its retention) in Terraform. Leave this
  # out for an existing deployment whose /aws/lambda/<name> group was already
  # auto-created, or import that group first:
  #   terraform import 'module.default.aws_cloudwatch_log_group.default[0]' /aws/lambda/cloudTrailConsole
  logs = {
    create            = true
    retention_in_days = 90
  }

  # slack does not need to be defined for cloudwatch logs to be emitted
  slack = {
    # If you have a single account
    # name = ":maple_leaf: NON-PRD"

    # channel = "#aws-console-actions"
    # webhook = "https://hooks.slack.com/services/T00000000/B00000000/XXXXXXXXXXXXXXXXXXXXXXXX"

    # If you have multiple accounts
    # accounts = {
    #   123456789012 = ":maple_leaf: NON-PRD"
    # }
  }

  tags = {
    terraform = true
    managedBy = "local_state"
  }
}
