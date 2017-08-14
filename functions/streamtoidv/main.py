import base64
import boto3
import json
import logging

from cis.libs import utils
from cis import processor


def handle(event, context):

    utils.StructuredLogger(
        name='cis-streamtoidv',
        level=logging.INFO
    )

    logger = logging.getLogger('cis-streamtoidv')

    logger.info("Stream Processor initialized.")

    for record in event['Records']:
        # Kinesis data is base64 encoded so decode here
        logger.info("Record is loaded.")

        payload = json.loads(
            base64.b64decode(record['kinesis']['data']).decode('utf-8')
        )

        logger.info("Initial payload decoded.")
        try:
            p = processor.StreamtoVaultOperation(
                boto_session=boto3.Session(region_name='us-west-2'),
                publisher=record['kinesis']['partitionKey'],
                signature=None,
                encrypted_profile_data=payload
            )

            res = p.run()
        except Exception as e:
            logger.error('Error writing to dynamo: {}'.format(e))
            res = False

        logger.info("Payload decrypted.  Attempting storage in the vault.")

        # Store the result of the event in the identity vault

        logger.info(
            "Vault storage status is {status}".format(
                status=res
            )
        )

    logger.info(
        'Successfully processed {} records.'.format(len(event['Records']))
    )

    return 'Successfully processed {} records.'.format(len(event['Records']))
