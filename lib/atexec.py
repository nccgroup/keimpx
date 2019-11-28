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
    sys.stderr.write('atexec: Impacket import error')
    sys.stderr.write('atexec: Impacket by SecureAuth Corporation is required for this tool to work. Please download it using:'
                     '\npip: pip install -r requirements.txt\nOr through your package manager:\npython-impacket.')
    sys.exit(255)


###############################################################
# Code borrowed and adapted from Impacket's atexec.py example #
###############################################################
class AtSvc(object):
    def __init__(self):
        pass

    def atexec(self, command):
        def output_callback(data):
            print(data.decode('utf-8'))

        if DataStore.version_major < 6:
            logger.warn('This command only works on Windows >= Vista')
            return

        self.__tmpFileName = ''.join([random.choice(string.letters) for _ in range(8)]) + '.tmp'
        self.__at_command = command
        self.__atsvc_connect()

        xml = """<?xml version="1.0" encoding="UTF-16"?>
        <Task version="1.2" xmlns="http://schemas.microsoft.com/windows/2004/02/mit/task">
          <Triggers>
            <CalendarTrigger>
              <StartBoundary>2015-07-15T20:35:13.2757294</StartBoundary>
              <Enabled>true</Enabled>
              <ScheduleByDay>
                <DaysInterval>1</DaysInterval>
              </ScheduleByDay>
            </CalendarTrigger>
          </Triggers>
          <Principals>
            <Principal id="LocalSystem">
              <UserId>S-1-5-18</UserId>
              <RunLevel>HighestAvailable</RunLevel>
            </Principal>
          </Principals>
          <Settings>
            <MultipleInstancesPolicy>IgnoreNew</MultipleInstancesPolicy>
            <DisallowStartIfOnBatteries>false</DisallowStartIfOnBatteries>
            <StopIfGoingOnBatteries>false</StopIfGoingOnBatteries>
            <AllowHardTerminate>true</AllowHardTerminate>
            <RunOnlyIfNetworkAvailable>false</RunOnlyIfNetworkAvailable>
            <IdleSettings>
              <StopOnIdleEnd>true</StopOnIdleEnd>
              <RestartOnIdle>false</RestartOnIdle>
            </IdleSettings>
            <AllowStartOnDemand>true</AllowStartOnDemand>
            <Enabled>true</Enabled>
            <Hidden>true</Hidden>
            <RunOnlyIfIdle>false</RunOnlyIfIdle>
            <WakeToRun>false</WakeToRun>
            <ExecutionTimeLimit>P3D</ExecutionTimeLimit>
            <Priority>7</Priority>
          </Settings>
          <Actions Context="LocalSystem">
            <Exec>
              <Command>cmd.exe</Command>
              <Arguments>/C %s &gt; %%windir%%\\Temp\\%s 2&gt;&amp;1</Arguments>
            </Exec>
          </Actions>
        </Task>
                """ % (self.__at_command, self.__tmpFileName)


        taskCreated = False
        try:
            logger.info('Creating task \\%s' % self.__tmpFileName)
            tsch.hSchRpcRegisterTask(self.__dce, '\\%s' % self.__tmpFileName, xml,
                                     tsch.TASK_CREATE, NULL, tsch.TASK_LOGON_NONE)
            taskCreated = True

            logger.info('Running task \\%s' % self.__tmpFileName)
            tsch.hSchRpcRun(self.__dce, '\\%s' % self.__tmpFileName)

            done = False
            while not done:
                logger.debug('Calling SchRpcGetLastRunInfo for \\%s' % self.__tmpFileName)
                resp = tsch.hSchRpcGetLastRunInfo(self.__dce, '\\%s' % self.__tmpFileName)
                if resp['pLastRuntime']['wYear'] != 0:
                    done = True
                else:
                    time.sleep(2)

            logger.info('Deleting task \\%s' % self.__tmpFileName)
            tsch.hSchRpcDelete(self.__dce, '\\%s' % self.__tmpFileName)
            taskCreated = False
        except tsch.DCERPCSessionError as e:
            logger.error(e)
            e.get_packet().dump()
        finally:
            if taskCreated is True:
                tsch.hSchRpcDelete(self.__dce, '\\%s' % self.__tmpFileName)

        self.transferClient = self.trans.get_smb_connection()
        waitOnce = True
        while True:
            try:
                logger.info('Attempting to read ADMIN$\\Temp\\%s' % self.__tmpFileName)
                self.transferClient.getFile('ADMIN$', 'Temp\\%s' % self.__tmpFileName, output_callback())
                break
            except Exception as e:
                if str(e).find('SHARING') > 0:
                    time.sleep(3)
                elif str(e).find('STATUS_OBJECT_NAME_NOT_FOUND') >= 0:
                    if waitOnce is True:
                        # We're giving it the chance to flush the file before giving up
                        time.sleep(3)
                        waitOnce = False
                    else:
                        raise
                else:
                    raise
        logger.debug('Deleting file ADMIN$\\Temp\\%s' % self.__tmpFileName)
        self.transferClient.deleteFile('ADMIN$', 'Temp\\%s' % self.__tmpFileName)
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
        self.__dce.bind(tsch.MSRPC_UUID_TSCHS)

    def __atsvc_disconnect(self):
        '''
        Disconnect from samr named pipe
        '''
        logger.debug('Disconnecting from the ATSVC named pipe')
        self.__dce.disconnect()
