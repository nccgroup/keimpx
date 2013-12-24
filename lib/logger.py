#!/usr/bin/env python
# -*- coding: iso-8859-15 -*-
# -*- Mode: python -*-

import logging
import sys

for handler in logging.root.handlers[:]:
    logging.root.removeHandler(handler)

logging.addLevelName(logging.ERROR, 'ERROR')
logging.addLevelName(logging.WARNING, 'WARNING')
logging.addLevelName(logging.CRITICAL, 'CRITICAL')
logging.addLevelName(logging.INFO, 'INFO')
logging.addLevelName(logging.DEBUG, 'DEBUG')

logger = logging.getLogger()
logger_handler = logging.StreamHandler(sys.stdout)
formatter = logging.Formatter('[%(asctime)s] [%(levelname)s] %(message)s', '%H:%M:%S')
logger_handler.setFormatter(formatter)
logger.addHandler(logger_handler)
logger.setLevel(logging.WARN)
