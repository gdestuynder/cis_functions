import base64
import json
import logging
import utils

from cis import validation, encryption

def handle(event, context):

    # Initialize Stream Logger
    # Log level can be environment driven later in development.
    log_level = logging.INFO
    utils.set_stream_logger(level=log_level)
    logger = logging.getLogger('cis-validator')
    logger.info("Stream Processor initialized.")

    for record in event['Records']:
        # Kinesis data is base64 encoded so decode here
        logger.info("Record is loaded.")

        payload = json.loads(
            base64.b64decode(record['kinesis']['data']).decode('utf-8')
        )

        logger.info("Initial payload decoded.")

        # Decrypt using the CIS library.  Each field is b64encoded as well.
        decrypted_payload = (
            json.loads(
                encryption.decrypt(
                    ciphertext=base64.b64decode(payload['ciphertext']),
                    ciphertext_key=base64.b64decode(payload['ciphertext_key']),
                    iv=base64.b64decode(payload['iv']),
                    tag=base64.b64decode(payload['tag'])
                )
            )
        )

        logger.info("Payload decrypted.  Attempting storage in the vault.")

        # Store the result of the event in the identity vault
        res = validation.store_to_vault(decrypted_payload)

        logger.info(
            "Vault storage status is {status}".format(
                status=res
            )
        )


        # To do scan the vault for this object.  If a version exists log.
        # Alternatively this could go to some sort of version table.

    logger.info(
        'Successfully processed {} records.'.format(len(event['Records']))
    )

    return 'Successfully processed {} records.'.format(len(event['Records']))
