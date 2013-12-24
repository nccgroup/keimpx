#!/usr/bin/env python
# -*- coding: iso-8859-15 -*-
# -*- Mode: python -*-

from lib.common import *

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
        self.__at_command = '%%COMSPEC%% /C %s > %%SystemRoot%%\\Temp\\%s\x00' % (os.path.basename(command.replace('\\', '/')), self.__tmpFileName)
        self.__atsvc_connect()

        logger.debug('Creating scheduled task with command: %s' % self.__at_command)

        # Check [MS-TSCH] Section 2.3.4
        self.__atInfo = atsvc.AT_INFO()
        self.__atInfo['JobTime']         = 0
        self.__atInfo['DaysOfMonth']     = 0
        self.__atInfo['DaysOfWeek']      = 0
        self.__atInfo['Flags']           = 0
        self.__atInfo['Command']         = ndrutils.NDRUniqueStringW()
        self.__atInfo['Command']['Data'] = (self.__at_command).encode('utf-16le')

        resp = self.__at.NetrJobAdd(('\\\\%s'% self.trans.get_dip()), self.__atInfo)
        jobId = resp['JobID']

        # Switching context to TSS
        self.__dce2 = self.__dce.alter_ctx(atsvc.MSRPC_UUID_TSS)

        # Now atsvc should use that new context
        self.__at = atsvc.DCERPCAtSvc(self.__dce2)

        resp = self.__at.SchRpcRun('\\At%d' % jobId)
        # On the first run, it takes a while the remote target to start executing the job
        # so I'm setting this sleep.. I don't like sleeps.. but this is just an example
        # Best way would be to check the task status before attempting to read the file
        logger.debug('Wait..')
        time.sleep(3)

        # Switching back to the old ctx_id
        self.__at = atsvc.DCERPCAtSvc(self.__dce)
        resp = self.__at.NetrJobDel('\\\\%s'% self.trans.get_dip(), jobId, jobId)
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
        self.__at = atsvc.DCERPCAtSvc(self.__dce)

    def __atsvc_disconnect(self):
        '''
        Disconnect from samr named pipe
        '''
        logger.debug('Disconnecting from the ATSVC named pipe')
        self.__dce.disconnect()
