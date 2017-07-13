#!/usr/bin/env python

# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at http://mozilla.org/MPL/2.0/.
# Copyright (c) 2017 Mozilla Corporation
# Contributors: Guillaume Destuynder <kang@mozilla.com>


import http.client
import json
import time
import logging
import utils


class DotDict(dict):
    """
    returns a dict.item notation for dict()'s
    """
    __getattr__ = dict.__getitem__
    __setattr__ = dict.__setitem__
    __delattr__ = dict.__delitem__

    def __init__(self, dct):
        for key, value in dct.items():
            if hasattr(value, 'keys'):
                value = DotDict(value)
            self[key] = value


class mozilliansorg():
    def __init__(self, decrypted_payload):
        log_level = logging.INFO
        utils.set_stream_logger(level=log_level)
        self.logger = logging.getLogger('CISFilter_mozilliansorg')
        self.validate(decrypted_payload)

    def validate(decrypted_payload):
        self.logger.debug("Attempting to validate incoming stream data")

