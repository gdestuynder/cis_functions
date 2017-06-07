#!/bin/bash


#####################################
# Only the auth0 connector needs    #
# a credstash grant to do what it   #
# does because of auth0 secrets.    #
# Everything else uses an IAM role  #
#####################################


region="us-east-1"

#Update the role here
role="CIS-Staging-Roles-IDVtoIDMDriver-1UOEZCZI1TOVR"
export AWS_DEFAULT_REGION="us-east-1"

#Grant command
credstash_key_id="`aws --region $region kms list-aliases --query "Aliases[?AliasName=='alias/credstash'].TargetKeyId | [0]" --output text`"
role_arn="`aws iam get-role --role-name $role --query Role.Arn --output text`"
constraints="EncryptionContextEquals={app=cis,environment=dev}"

aws kms create-grant --key-id $credstash_key_id --grantee-principal $role_arn --operations "Decrypt" --constraints $constraints --name idv-to-idm
