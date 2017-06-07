# cis_functions
Home of the serverless functions for https://github.com/mozilla-iam/cis

All of the issues for higher level stories are captured here:
https://github.com/mozilla-iam/cis/issues

## Requirements

* Apex http://apex.run/

# Deploying the project as an administrator

1. Deploy the Cloudformation templates
2. Update the role ARNs for your development account in the respective project.json and function.json file(s)

# Deploying the project as a developer

1. Clone the project.
2. Install aws-mfa `pip install aws-mfa`
3. Edit your ~/.aws/credentials file and create a profile that looks like this with
static access keys that give you the ability to assume_role.

```
[defult-long-term]
aws_access_key_id = YOUR_LONGTERM_KEY_ID
aws_secret_access_key = YOUR_LONGTERM_ACCESS_KEY
```

I set up a bash alias for convenience after this that looks like:


alias idaws="/Users/akrug/Library/Python/2.7/bin/aws-mfa --device arn:aws:iam::371522382791:mfa/akrug --assume-role arn:aws:iam::656532927350:role/CISDeveloper --role-session-name \"andrew-mac\""

> Note this should work for any parsys infra account user with MFA.  

My credentials generated in this manner are good for 60-minutes.  I could set up additional aliases for additional profiles if necessary.

After this you can do some iterating on your functions.  One of the really great things about Apex is that you can pass events on stdin via the apex cli for testing.  They actually end up invoked in lambda and return stdout/stderr.

Example: `apex invoke -e dev validator < functions/hello/event.json`

> -e indicates the environment in the name function.dev.json

Do not forget though every time you make a code change locally and want to publish to test you must apex deploy.

Deploy using `apex deploy -e dev`

# AutoLinting
Automatic linting with pep8 is currently setup via travis-ci.

# Deploying using the Docker Container ( recommended )

See the container project for the reasons why you'd want to use the container instead:

1. Run a shell in the prepacked lambda container environment.

`docker run --rm -ti -v ~/.aws:/root/.aws -v ~/workspace/cis_functions/:/workspace mozillaiam/docker-apex:latest /bin/bash`

2. Do business as usual.  

# CI/CD pipelines

1. Commits to master branch automatically run `apex deploy -e stage`

> This environment is a fully self contained version of the vault, stream, and dynamo.  However users should note that it still updates manage-dev instance of auth0.
 
