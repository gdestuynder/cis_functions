#!/bin/bash


#####################################
# Only the auth0 connector needs    #
# a credstash grant to do what it   #
# does because of auth0 secrets.    #
# Everything else uses an IAM role  #
#####################################


region="us-west-2"

#Update the role here
role="cis-prod-roles-IDVtoIDMDriver-1RCFMGZADHHFK"
export AWS_DEFAULT_REGION="us-west-2"

#Grant command
credstash_key_id="`aws --region $region kms list-aliases --query "Aliases[?AliasName=='alias/credstash'].TargetKeyId | [0]" --output text`"
role_arn="`aws iam get-role --role-name $role --query Role.Arn --output text`"
constraints="EncryptionContextEquals={app=cis,environment=prod}"

aws kms create-grant --key-id $credstash_key_id --grantee-principal $role_arn --operations "Decrypt" --constraints $constraints --name idv-to-idm
