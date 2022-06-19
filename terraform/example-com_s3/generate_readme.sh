#!/bin/bash
BACKTICK='`'
cat << EOF > README.md
# Getting Started with Terraform S3 Module

${BACKTICK}${BACKTICK}${BACKTICK}hcl
$(cat ./lambda.tf)
${BACKTICK}${BACKTICK}${BACKTICK}

$(terraform-docs markdown ../modules/cloudtrailconsole/s3)
EOF
