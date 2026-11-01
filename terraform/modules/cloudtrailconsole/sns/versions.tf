# Minimums: optional() attribute defaults in variable types need Terraform
# 1.3, and data.aws_region.current.region needs AWS provider 6.0.
terraform {
  required_version = ">= 1.3"

  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = ">= 6.0"
    }
    archive = {
      source  = "hashicorp/archive"
      version = ">= 2.4"
    }
  }
}
