__version__ = '0.0.1'

import os
import logging
import time
from datetime import datetime


def set_stream_logger(name="cis-validator", level=logging.INFO,
                      format_string=None):
    """
    """

    if format_string is None:
        format_string = "%(asctime)s - %(name)s - %(levelname)s - %(message)s"
    time_format = "%Y-%m-%dT%H:%M:%S"

    logger = logging.getLogger(name)
    logger.setLevel(level)
    streamHandler = logging.StreamHandler()
    streamHandler.setLevel(level)
    streamFormatter = logging.Formatter(format_string, time_format)
    streamHandler.setFormatter(streamFormatter)
    logger.addHandler(streamHandler)

class NullHandler(logging.Handler):
    def emit(self, record):
        pass

logging.getLogger('cis-validator').addHandler(NullHandler())
