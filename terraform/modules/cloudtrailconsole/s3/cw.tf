resource "aws_cloudwatch_log_group" "default" {
  count             = var.logs["create"] ? 1 : 0
  name              = "/aws/lambda/${var.name}"
  retention_in_days = var.logs["retention_in_days"]
  skip_destroy      = var.logs["skip_destroy"]
  log_group_class   = var.logs["log_group_class"]
  kms_key_id        = var.logs["kms_key_id"]

  tags = merge(
    var.tags,
    {
      Name = "/aws/lambda/${var.name}"
    }
  )
}
