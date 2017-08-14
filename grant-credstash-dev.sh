#!/bin/bash

region="us-west-2"
credstash_key_id="`aws --region $region kms list-aliases --query "Aliases[?AliasName=='alias/credstash'].TargetKeyId | [0]" --output text`"
role_arn="`aws iam get-role --role-name CISLambdaFunctionRoles-IDVtoIDMDriver-22W44UZPPRSX --query Role.Arn --output text`"
constraints="EncryptionContextEquals={app=cis,environment=dev}"

# Grant the sso-dashboard IAM role permissions to decrypt
aws kms create-grant --key-id $credstash_key_id --grantee-principal $role_arn --operations "Decrypt" --constraints $constraints --name cis-dev
