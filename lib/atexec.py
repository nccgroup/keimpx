#!/usr/bin/env python
# -*- coding: iso-8859-15 -*-
# -*- Mode: python -*-

from lib.common import DataStore
from lib.logger import logger
import shlex
import random
import os
import sys
import time
import string
import ntpath

try:
    from impacket.dcerpc.v5 import atsvc
    from impacket.dcerpc.v5.dtypes import NULL
    from impacket.dcerpc.v5 import tsch
except ImportError:
    sys.stderr.write('atexec: Impacket by SecureAuth Corporation is required for this tool to work. Please download it using:'
                     '\npip: pip install -r requirements.txt\nOr through your package manager:\npython-impacket.')
    sys.exit(255)


###############################################################
# Code borrowed and adapted from Impacket's atexec.py example #
###############################################################
class AtSvc(object):
    def __init__(self):
        pass

    def __output_callback(self, data):
        print data

    def atexec(self, command):
        if DataStore.version_major < 6:
            logger.warn('This command only works on Windows >= Vista')
            return

        command_and_args = shlex.split(command)

        if os.path.exists(command_and_args[0]):
            self.use(DataStore.writable_share)
            self.upload(command_and_args[0])

        self.__tmpFileName = ''.join([random.choice(string.letters) for i in range(8)]) + '.tmp'
        self.__at_command = '%%COMSPEC%% /C %s > %%SystemRoot%%\\Temp\\%s\x00' % (
            os.path.basename(command.replace('\\', '/')), self.__tmpFileName)
        self.__atsvc_connect()

        logger.debug('Creating scheduled task with command: %s' % self.__at_command)

        # Check [MS-TSCH] Section 2.3.4
        self.__atInfo = atsvc.AT_INFO()
        self.__atInfo['JobTime'] = 0
        self.__atInfo['DaysOfMonth'] = 0
        self.__atInfo['DaysOfWeek'] = 0
        self.__atInfo['Flags'] = 0
        self.__atInfo['Command'] = ('%%COMSPEC%% /C %s > %%SYSTEMROOT%%\\Temp\\%s 2>&1\x00'
                                    % (self.__command, self.__tmpFileName))

        resp = atsvc.hNetrJobAdd(self.__dce, NULL, self.__atInfo)
        jobId = resp['pJobID']

        # Switching context to TSS
        self.__dce2 = self.__dce.alter_ctx(tsch.MSRPC_UUID_TSCHS)

        resp = tsch.hSchRpcRun(self.__dce2, '\\At%d' % jobId)
        # On the first run, it takes a while the remote target to start executing the job
        # so I'm setting this sleep.. I don't like sleeps.. but this is just an example
        # Best way would be to check the task status before attempting to read the file
        logger.debug('Wait..')
        time.sleep(3)

        # Switching back to the old ctx_id
        atsvc.hNetrJobDel(self.__dce, NULL, jobId, jobId)
        self.__tmpFilePath = ntpath.join('Temp', self.__tmpFileName)
        self.transferClient = self.trans.get_smb_connection()

        while True:
            try:
                self.transferClient.getFile(self.share, self.__tmpFilePath, self.__output_callback)
                break
            except Exception, e:
                if str(e).find('SHARING') > 0:
                    time.sleep(3)
                else:
                    raise

        self.transferClient.deleteFile(self.share, self.__tmpFilePath)
        self.__atsvc_disconnect()

    def __atsvc_connect(self):
        '''
        Connect to atsvc named pipe
        '''
        self.check_share(DataStore.writable_share)

        logger.debug('Connecting to the ATSVC named pipe')
        self.smb_transport('atsvc')

        logger.debug('Binding on Task Manager (ATSVC) interface')
        self.__dce = self.trans.get_dce_rpc()
        self.__dce.set_credentials(*self.trans.get_credentials())
        self.__dce.connect()
        self.__dce.bind(atsvc.MSRPC_UUID_ATSVC)

    def __atsvc_disconnect(self):
        '''
        Disconnect from samr named pipe
        '''
        logger.debug('Disconnecting from the ATSVC named pipe')
        self.__dce.disconnect()
