""" Mozilla Change Integration Service Validator.

This lambda function is invoked by a change integration service producer like
mozillians.org.

Call:  synchronously using boto3('lambda') client.
Takes: an event containing a user profile
Does:  validate the user profile against the json schema for Mozilla users.

If the profile passes store it in kinesis for processing.

"""
import logging
import os
import utils

# Import the Mozilla CIS library to facilitate core logic interaction.
from cis import encryption, streams, validation


def handle(event, context):
    """This is the main handler called during function invocation."""

    # Initialize Stream Logger
    # Log level can be environment driven later in development.
    log_level = logging.INFO
    utils.set_stream_logger(level=log_level)
    logger = logging.getLogger('cis-validator')
    logger.info("Validator successfully initialized.")

    payload_status = validation.validate(**event)
    if payload_status is True:
        logger.info("Payload is valid sending to kinesis.")
        # To-Do Write to kinesis
        streams.publish_to_cis(data=encryption.decrypt(**event), partition_key='mozillians.org')

        # Call Invoke-Function to start vault stream processor.
    else:
        logger.info("Payload is invalid rejecting payload.")

        # To-Do Raise Exception back to invoking party.


def wrapper():
    """Helper for easily calling this from a command line locally.
    Example: `python -c 'import main; main.wrapper()' | jq '.'`

    Only present to facilitate local testing without uploading to
    lambda.  Remove wrapper for production release.  Wrapper() concept
    courtesy of Graham Jones from ThreatResponse.
    """

    event_file = os.path.join(
        os.path.abspath(os.path.dirname(__file__)), 'event-krug.json'
    )

    with open(event_file, 'r') as event_data:
        event = (event_data.read().encode('utf-8'))

    event = encryption.encrypt(event)
    handle(event, None)
