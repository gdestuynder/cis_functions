""" Mozilla Change Integration Service Validator.

This lambda function is invoked by a change integration service producer like
mozillians.org.

Call:  synchronously using boto3('lambda') client.
Takes: an event containing a user profile
Does:  validate the user profile against the json schema for Mozilla users.

If the profile passes store it in kinesis for processing.

"""
import base64
import boto3
import json
import logging

# Import the Mozilla CIS library to facilitate core logic interaction.
from cis.libs import utils
from cis import processor


def handle(event, context):
    """This is the main handler called during function invocation."""

    utils.StructuredLogger(
        name='cis-validator',
        level=logging.INFO
    )

    logger = logging.getLogger('cis-validator')

    encrypted_profile_data = json.loads(base64.b64decode(event.get('profile')))

    p = processor.ValidatorOperation(
        boto_session=boto3.Session(region_name='us-west-2'),
        publisher=event.get('publisher'),
        signature=event.get('signature'),
        encrypted_profile_data=encrypted_profile_data
    )

    result = p.run()

    logger.info('The result of the change operation was {r}'.format(r=result))

    return result
