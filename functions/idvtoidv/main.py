import logging
import utils


def handle(event, context):

    # Initialize Stream Logger
    # Log level can be environment driven later in development.
    log_level = logging.INFO
    utils.set_stream_logger(level=log_level)
    logger = logging.getLogger('cis-idvtoidv')
    logger.info("Stream Processor initialized.")

    for record in event['Records']:
        pass
    return None
