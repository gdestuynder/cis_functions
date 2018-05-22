"""
This is the body of the lambda function for the Auth0 Identity driver of CIS
This function retrieves user profiles from the CIS ID Vault and sends the appropriate data to the Auth0 API
which is in turn used to create the id_token JWT and fill the user info endpoint ('profile' scope)
"""
import authzero
import boto3
import credstash
import json
import os
import yaml
import re

from botocore.exceptions import ClientError

from cis.libs import utils
from cis.settings import get_config

config = get_config()


def find_user(user_id):
    # XXX TBD replace this with person-api call or LDAP publisher.
    table_name = os.getenv('CIS_DYNAMODB_TABLE', None)
    dynamodb = boto3.resource('dynamodb', region_name='us-west-2')
    table = dynamodb.Table(table_name)
    try:
        res = table.get_item(
            Key={
                'user_id': user_id
            }
        )
        profile = res.get('Item', None)

        # Fix null values workaround for DynamoDB limitation
        if profile and profile['groups'] == 'NULL':
            profile['groups'] = []

        if profile and profile.get('authoritativeGroups') and profile['authoritativeGroups'] == 'NULL':
            profile['authoritativeGroups'] = []

        return profile
    except ClientError:
        return None


def handle(event, context):
    os.environ['TZ'] = 'UTC' # Default to UTC for all timestamps
    config = get_config()
    custom_logger = utils.CISLogger(
        name=__name__,
        level=config('logging_level', namespace='cis', default='INFO'),
        cis_logging_output=config('logging_output', namespace='cis', default='stream'),
        cis_cloudwatch_log_group=config('cloudwatch_log_group', namespace='cis', default='')
    ).logger()

    logger = custom_logger.get_logger()
    logger.info('Stream Processor initialized for stage: idvtoauth0.')

    environment = os.getenv('ENVIRONMENT', 'dev')

    if environment == 'production':
        environment = 'prod'
    else:
        logger.info('Development stage recognized.  Applying to credstash.')
        environment = 'dev'

    # New up the config object for CISAuthZero
    config = authzero.DotDict(dict())
    config.client_id = credstash.getSecret(
        name="cis.client_id",
        context={'app': 'cis', 'environment': environment},
        region="us-west-2"
    )

    config.client_secret = credstash.getSecret(
        name="cis.client_secret",
        context={'app': 'cis', 'environment': environment},
        region="us-west-2"
    )

    config.uri = credstash.getSecret(
        name="cis.uri",
        context={'app': 'cis', 'environment': environment},
        region="us-west-2"
    )

    client = authzero.CISAuthZero(config)
    client.get_access_token()

    for record in event['Records']:
        # Kinesis data is base64 encoded so decode here
        user_id = record['dynamodb']['Keys']['user_id']['S']

        logger.info('Processing record for user: {}'.format(user_id))
        logger.info('Searching for dynamo record for user: {}'.format(user_id))

        profile = find_user(user_id)
        if profile is not {} or None:
            logger.info('A profile has been located for user: {}'.format(user_id))

        if profile is not None:
            logger.info('Attempting to reintegrate profile for user: {}'.format(user_id))
            logger.debug('-------------------Pre-Integration---------------------------')
            logger.debug(json.dumps(profile))
            logger.debug('------------------------End----------------------------------')

            compatible_group_list = []
            # Strip the LDAP prefix from LDAP groups for compatibility
            for group in profile.get('groups'):
                if group.startswith('ldap_'):
                    compatible_group_list.append(re.sub('ldap_', '', group))
                else:
                    compatible_group_list.append(group)


            # Fetch auth0 profile
            aprofile = client.get_user(user_id)
            aprofile_groups = aprofile['app_metadata'].get('authoritativeGroups')
            # What's in our new groups that arent in auth0?
            new_groups = set(compatible_group_list) - set(aprofile_groups)

            logger.info('Retrieved auth0 user: {}'.format(user_id))
            logger.debug('-------------------Auth0-Response----------------------------')
            logger.debug(json.dumps(aprofile))
            logger.debug('New groups to add to auth0: {}'.format(new_groups))
            logger.debug('------------------------End----------------------------------')

            ## Bootstrap expiration of access (authoritativeGroups) where needed
            logger.info('Start authoritativeGroups bootstrapping for user: {}'.format(user_id))
            logger.debug('-----------Bootstrapping authoritativeGroups-----------------')
            authoritativeGroups = profile.get('authoritativeGroups')
            # Fetch apps.yml access information data
            # XXX Should this be cached?
            access_rules_url = os.getenv('IAM_ACCESS_RULES_URL')
            r = requests.get(access_rules_url)
            if not r.ok:
                logger.warning('Failed to fetch access rules: url: {}, reason: {}, code: {}, body: {}'
                             .format(r.url, r.reason, r.status_code, r.text))
                logger.warning('No expiration stamp will be set for user: {} (failing closed)'.format(user_id))
            else:
                try:
                    access_rules = yaml.load(r.text)
                except Exception as e:
                    logger.warning('Failed to parse the access rules, no expiration stamp will be set for user: {}, '
                                   'exception: {} (failing closed)'.format(user_id, e))
                else:
                    # Do we have an expiration of access authoritativeGroups for our RPs?
                    for rule in access_rules.get('apps'):
                        if rule['application'] get('expire_access_when_unused_after') is not None:
                            # Does the user profile on auth0 already have this group implemented?
                            afound = False # Records if we found a match
                            for existing_agroup in profile['authoritativeGroups']:
                                if rule['application'].get('client_id') == existing_agroup.get('uuid'):
                                    logger.debug('User {} already have a timestamp set for client_id {}, skipping'
                                                 .format(user_id, existing_agroup.get('uuid')))
                                    afound = True
                                    break
                            # No match, so the user has no authoritativeGroups timestamp for this RP, but the RP uses
                            # expiration of access. We add it here so that we know of when the access has been first
                            # given to the user, even if the user never logs in to the RP. This line is the whole reason
                            # all this code is there. The timestamp is in "js" format.
                            if not afound:
                                authoritativeGroups.append({'lastUsed': time.strftime('%Y-%m-%dT%H:%M:%S.000Z'),
                                                            'uuid': rule['application'].get('client_id'}
                                                          )
            logger.debug('------------------------End----------------------------------')

            # Update groups only in Auth0
            profile_update = {'groups': compatible_group_list, 'authoritativeGroups': authoritativeGroups}

            res = client.update_user(user_id, profile_groups)
            logger.info('Updating user group information in auth0 for {}'.format(user_id))
            logger.debug('-------------------Post-Integration--------------------------')
            logger.debug(json.dumps(profile))
            logger.debug('------------------------End----------------------------------')

            logger.info('Auth0 processing complete for for user: {}'.format(res, user_id))
            logger.debug('-------------------Auth0-Response-----------------------------')
            logger.debug(res)
            logger.debug('------------------------End----------------------------------')
        else:
            logger.critical(
                'User could not be matched in vault for userid : {}'.format(user_id)
            )

    logger.info(
        'IDVTOAUTH0: Successfully processed {} records.'.format(len(event['Records']))
    )

    return 'IDVTOAUTH0: Successfully processed {} records.'.format(len(event['Records']))
