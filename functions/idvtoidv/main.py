import logging
from cis import utils


def handle(event, context):

    sl = utils.StructuredLogger(
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
