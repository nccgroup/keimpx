#!/usr/bin/env python
# -*- coding: iso-8859-15 -*-
# -*- Mode: python -*-

from lib.common import *

###############################################################
# Code borrowed and adapted from Impacket's psexec.py example #
###############################################################
class PsExec(object):
    def __init__(self):
        pass

    def __output_callback(self, data):
        print data

    def psexec(self, command=''):
        if not command:
            logger.info('Command has not been specified, going to call cmd.exe')
            command = 'cmd.exe'
