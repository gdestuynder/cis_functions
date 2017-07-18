""" Mozilla Change Integration Service Validator.

This lambda function is invoked by a change integration service producer like
mozillians.org.

Call:  synchronously using boto3('lambda') client.
Takes: an event containing a user profile
Does:  validate the user profile against the json schema for Mozilla users.

If the profile passes store it in kinesis for processing.

"""
import base64
import logging

# Import the Mozilla CIS library to facilitate core logic interaction.
from cis import encryption
from cis import streams
from cis import validation
from cis import utils

def handle(event, context):
    """This is the main handler called during function invocation."""

    sl = utils.StructuredLogger(
        name='cis-validator',
        level=logging.INFO
    )

    logger = logging.getLogger('cis-validator')

    payload = {}
    payload['ciphertext'] = base64.b64decode(event['ciphertext'])
    payload['tag'] = base64.b64decode(event['tag'])
    payload['ciphertext_key'] = base64.b64decode(event['ciphertext_key'])
    payload['iv'] = base64.b64decode(event['iv'])

    # Require publisher to add partition key in event
    publisher = str(base64.b64decode(event.get('publisher').decode('utf-8')))


    # Initialize Stream Logger
    # Log level can be environment driven later in development.

    logger.info("Validator successfully initialized.")

    payload_status = validation.validate(publisher, **payload)

    if payload_status is True:
        logger.info("Payload is valid sending to kinesis.")

        decrypted_profile = encryption.decrypt(**payload)

        res = streams.publish_to_cis(
            data=decrypted_profile,
            partition_key=publisher
        )

        return True
    else:
        logger.info("Payload is invalid rejecting payload.")
        return False

