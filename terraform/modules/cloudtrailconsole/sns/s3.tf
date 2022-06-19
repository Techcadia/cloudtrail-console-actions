data "aws_s3_bucket" "default" {
  bucket = var.s3["name"]
}
