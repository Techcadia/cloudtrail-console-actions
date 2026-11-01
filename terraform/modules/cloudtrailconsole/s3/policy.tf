# A custom policy ships as a Lambda layer holding policy.yaml, which Lambda
# extracts to /opt. Without one the function uses its embedded default.
data "archive_file" "policy" {
  count       = var.policy != null ? 1 : 0
  type        = "zip"
  output_path = "${path.root}/.terraform/cloudtrailconsole-${var.name}-policy.zip"

  source {
    content  = var.policy
    filename = "policy.yaml"
  }
}

resource "aws_lambda_layer_version" "policy" {
  count                    = var.policy != null ? 1 : 0
  layer_name               = "${var.name}-policy"
  description              = "CloudTrail Console Actions filter policy"
  filename                 = data.archive_file.policy[0].output_path
  source_code_hash         = data.archive_file.policy[0].output_base64sha256
  compatible_runtimes      = [lookup(var.lambda, "runtime", "provided.al2023")]
  compatible_architectures = lookup(var.lambda, "architectures", ["arm64"])
}
