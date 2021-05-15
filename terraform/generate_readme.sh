#!/bin/bash
BACKTICK='`'
cat << EOF > README.md
# Getting Started with Terraform

${BACKTICK}${BACKTICK}${BACKTICK}hcl
$(cat ./example-com/lambda.tf)
${BACKTICK}${BACKTICK}${BACKTICK}

$(terraform-docs markdown modules/cloudtrailconsole/)
EOF
