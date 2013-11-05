#!/usr/bin/env python
# -*- coding: iso-8859-15 -*-
# -*- Mode: python -*-

import logging
import sys

logger = logging.getLogger('logger')
logger_handler = logging.StreamHandler(sys.stdout)
formatter = logging.Formatter('[%(asctime)s] [%(levelname)s] %(message)s', '%H:%M:%S')
logger_handler.setFormatter(formatter)
logger.addHandler(logger_handler)
logger.setLevel(logging.WARN)
