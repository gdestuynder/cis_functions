import logging

from cis.libs import utils


def handle(event, context):

    utils.StructuredLogger(
        name='cis-idvtoidv',
        level=logging.INFO
    )

    # Initialize Stream Logger
    # Log level can be environment driven later in development.
    logger = logging.getLogger('cis-idvtoidv')
    logger.info("Stream Processor initialized.")

    for record in event['Records']:
        pass
    return None
