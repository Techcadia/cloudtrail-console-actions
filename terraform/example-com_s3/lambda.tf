module "default" {
  source = "../modules/cloudtrailconsole"
  name   = "cloudTrailConsole"

  s3 = {
    name = "example-com-non-prd-cloudtrail"
  }

  lambda = {
    # **Note**: Increase memory if you are experiencing slow s3 reads"
    memory                         = 128
    timeout                        = 15
    reserved_concurrent_executions = 10
    environment_variables          = {}
    # **Note**: Depending on your Terraform directory structure you might need to define the filepath.
    filepath = "../../../cloudtrail-console-actions/dist/function.zip"
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
