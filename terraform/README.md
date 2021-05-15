# Getting Started with Terraform

```hcl
module "default" {
  source = "../modules/cloudtrailconsole"
  name   = "cloudTrailConsole"

  s3 = {
    name = "example-com-non-prd-cloudtrail"
  }

  lambda = {
    # **Note**: Increase memory if you are experiencing slow s3 reads"
    # memory                         = 128
    # timeout                        = 15
    # reserved_concurrent_executions = 10
    # environment_variables          = {}
    # **Note**: Depending on your Terraform directory structure you might need to define the filepath.
    # filepath                       = "../cloudtrail-console-actions/dist/function.zip"
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
```

## Requirements

No requirements.

## Providers

| Name | Version |
|------|---------|
| <a name="provider_aws"></a> [aws](#provider\_aws) | n/a |

## Modules

No modules.

## Resources

| Name | Type |
|------|------|
| [aws_iam_role.default](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/iam_role) | resource |
| [aws_iam_role_policy.default](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/iam_role_policy) | resource |
| [aws_lambda_function.default](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/lambda_function) | resource |
| [aws_lambda_permission.default](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/lambda_permission) | resource |
| [aws_s3_bucket_notification.default](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/s3_bucket_notification) | resource |
| [aws_caller_identity.current](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/data-sources/caller_identity) | data source |
| [aws_iam_policy_document.default](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/data-sources/iam_policy_document) | data source |
| [aws_iam_policy_document.sts](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/data-sources/iam_policy_document) | data source |
| [aws_s3_bucket.default](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/data-sources/s3_bucket) | data source |

## Inputs

| Name | Description | Type | Default | Required |
|------|-------------|------|---------|:--------:|
| <a name="input_lambda"></a> [lambda](#input\_lambda) | Lambda Settings | `any` | `{}` | no |
| <a name="input_name"></a> [name](#input\_name) | Name of the Lambda, IAM Role and CloudWatch Log Groups | `string` | `"cloudTrailConsole"` | no |
| <a name="input_s3"></a> [s3](#input\_s3) | S3 Bucket Settings | `any` | `{}` | no |
| <a name="input_slack"></a> [slack](#input\_slack) | Slack Settings | `any` | `{}` | no |
| <a name="input_tags"></a> [tags](#input\_tags) | A mapping of tags to supply to the resources | `map(string)` | `{}` | no |

## Outputs

| Name | Description |
|------|-------------|
| <a name="output_aws_caller_identity"></a> [aws\_caller\_identity](#output\_aws\_caller\_identity) | The AWS caller identity value used for grabbing account\_id, current user, etc. |
| <a name="output_default"></a> [default](#output\_default) | Returns a nested map of the configured resources |
