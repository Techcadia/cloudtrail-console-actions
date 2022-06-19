#!/bin/bash
BACKTICK='`'
cat << EOF > README.md
# Getting Started with Terraform SNS Module

${BACKTICK}${BACKTICK}${BACKTICK}hcl
$(cat ./lambda.tf)
${BACKTICK}${BACKTICK}${BACKTICK}

$(terraform-docs markdown ../modules/cloudtrailconsole/sns)
EOF
