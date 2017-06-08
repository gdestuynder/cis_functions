""" This is the body of the lambda function """
import authzero
import boto3
import credstash
import logging
import os
import utils

from botocore.exceptions import ClientError


# TODO: function should move to CIS core.
def find_user(user_id):
    table_name = os.getenv('CIS_DYNAMODB_TABLE', None)
    dynamodb = boto3.resource('dynamodb', region_name='us-west-2')
    table = dynamodb.Table(table_name)
    try:
        res = table.get_item(
            Key={
                'user_id': user_id
            }
        )
        return res.get('Item', None)
    except ClientError:
        return None


def handle(event, context):

    # Initialize Stream Logger
    # Log level can be environment driven later in development.
    log_level = logging.INFO
    utils.set_stream_logger(level=log_level)
    logger = logging.getLogger('cis-idvtoauth0')
    logger.info("Stream Processor initialized.")

    # New up the config object for CISAuthZero
    config = authzero.DotDict(dict())
    config.client_id = credstash.getSecret(
        name="cis.client_id",
        context={'app': 'cis', 'environment': 'dev'},
        region="us-east-1"
    )

    config.client_secret = credstash.getSecret(
        name="cis.client_secret",
        context={'app': 'cis', 'environment': 'dev'},
        region="us-east-1"
    )

    config.uri = credstash.getSecret(
        name="cis.uri",
        context={'app': 'cis', 'environment': 'dev'},
        region="us-east-1"
    )

    client = authzero.CISAuthZero(config)
    client.get_access_token()

    for record in event['Records']:
        # Kinesis data is base64 encoded so decode here
        logger.info("Record is loaded.")
        logger.info("Processing {record}".format(record=record))
        user_id = record['dynamodb']['Keys']['user_id']['S']

        logger.info("Initial payload decoded.")
        logger.info("Searching for dynamo record for {u}".format(u=user_id))
        profile = find_user(user_id)

        logger.info("Status of profile search is {s}".format(s=profile))

        if profile is not None:
            # XXX Force-integrate LDAP groups as these are synchronized
            # from LDAP to Auth0 directly.
            # This is to be removed when LDAP feeds CIS.
            upstream_user = client.get_user(user_id)

            if 'groups' in upstream_user.keys():
                for g in upstream_user['groups']:
                    if g not in profile['groups']:
                        profile['groups'].append(g)
                        logger.info("Forced re-integration of LDAP group {}".format(g))

            res = client.update_user(user_id, profile)
            logger.info("Status of message processing is {s}".format(s=res))
        else:
            logger.critical(
                "User could not be matched in vault for userid : {user_id}".format(user_id=user_id)
            )

    logger.info(
        'Successfully processed {} records.'.format(len(event['Records']))
    )

    return 'Successfully processed {} records.'.format(len(event['Records']))
