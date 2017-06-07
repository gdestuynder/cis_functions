# About Cloudformation for this Project

Since apex doesn't have many IAM features and we don't want to give the equivalent
of *:* to these functions the roles will be created by Cloudformation.

For granularity and greater control one role per function in the pipeline has been
scoped here in the CF template.

Role ARNs for Development:

  - arn:aws:iam::656532927350:role/CISLambdaFunctionRoles-StreamValidator-12UNGHKGTAIIK
  - arn:aws:iam::656532927350:role/CISLambdaFunctionRoles-StreamToIDV-T5IH2261NJZM
  - arn:aws:iam::656532927350:role/CISLambdaFunctionRoles-IDVtoIDV-8AMFBTKC70WN
  - arn:aws:iam::656532927350:role/CISLambdaFunctionRoles-IDVtoIDMDriver-22W44UZPPRSX

## Steps to get the environment setup.

1. Run the cloudformation stack that creates the IAM roles.
2. Update the roles for your environment in functions.json.
3. Add the credstash grant using `grant-credstash.sh` for the authzero connector.
4. (optional) If this is a new AWS Account you may need to add credstash secrets for authzero to credstash.
5. Deploy the functions using `apex -e $ENVIRONMENT deploy`
6. Setup the event handlers and identity vault.  You will need to supply the ARNs of authzeros function and the
stream to vault function.
7. Take note of the ARN of the DynamoDB and CISInput stream.  Add those to function.*.json for the environment and
redeploy using `apex -e $ENVIRONMENT deploy`

> Note: should a function ever be undeployed the event system will need to be setup again.