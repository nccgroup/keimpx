#!/usr/bin/env python
# -*- coding: iso-8859-15 -*-
# -*- Mode: python -*-

from lib.common import *

###############################################################
# Code borrowed and adapted from Impacket's psexec.py example #
###############################################################
class RemComMessage(Structure):
    structure = (
        ('Command','4096s=""'),
        ('WorkingDir','260s=""'),
        ('Priority','<L=0x20'),
        ('ProcessID','<L=0x01'),
        ('Machine','260s=""'),
        ('NoWait','<L=0'),
    )

class RemComResponse(Structure):
    structure = (
        ('ErrorCode','<L=0'),
        ('ReturnCode','<L=0'),
    )

RemComSTDOUT = "RemCom_stdout"
RemComSTDIN = "RemCom_stdin"
RemComSTDERR = "RemCom_stderr"

lock = Lock()

class PsExec(object):
    def __init__(self):
        pass

    def psexec(self, command=None):
        srvname = ''.join([random.choice(string.letters) for _ in range(8)])
        remote_file = '%s.exe' % ''.join([random.choice(string.lowercase) for _ in range(8)])

        if not command:
            logger.info('Command has not been specified, going to call cmd.exe')
            command = 'cmd.exe'

        if command in ('cmd.exe', 'command.com'):
            logger.info('Launching interactive OS shell')

        command_and_args = shlex.split(command)

        if os.path.exists(command_and_args[0]):
            self.use(DataStore.writable_share)
            self.upload(command_and_args[0])

        logger.debug('Going to use temporary service %s' % srvname)

        self.deploy(srvname, remcomsvc.RemComSvc(), '', remote_file)
        self.smb_transport('svcctl')
        self.__smb = self.trans.get_smb_connection()
        self.__smb.setTimeout(100000)
        self.__tid = self.__smb.connectTree('IPC$')
        self.__fid_main = self.openPipe(self.__smb, self.__tid, '\RemCom_communicaton', 0x12019f)

        packet = RemComMessage()
        packet['Machine'] = ''.join([random.choice(string.letters) for i in range(4)])
        packet['Command'] = os.path.basename(command.replace('\\', '/'))
        packet['ProcessID'] = os.getpid()

        self.__smb.writeNamedPipe(self.__tid, self.__fid_main, str(packet))

        # Here we'll store the command we type so we don't print it back ;)
        # ( I know.. globals are nasty :P )
        global LastDataSent
        LastDataSent = ''

        # Create the pipes threads
        stdin_pipe = RemoteStdInPipe(self.trans, '\%s%s%d' % (RemComSTDIN, packet['Machine'], packet['ProcessID']), smb.FILE_WRITE_DATA | smb.FILE_APPEND_DATA, self.share)
        stdin_pipe.start()
        stdout_pipe = RemoteStdOutPipe(self.trans, '\%s%s%d' % (RemComSTDOUT, packet['Machine'], packet['ProcessID']), smb.FILE_READ_DATA)
        stdout_pipe.start()
        stderr_pipe = RemoteStdErrPipe(self.trans, '\%s%s%d' % (RemComSTDERR, packet['Machine'], packet['ProcessID']), smb.FILE_READ_DATA)
        stderr_pipe.start()

        # And we stay here till the end
        ans = self.__smb.readNamedPipe(self.__tid, self.__fid_main, 8)

        if len(ans):
           retCode = RemComResponse(ans)
           logger.info('Process %s finished with ErrorCode: %d, ReturnCode: %d' % (os.path.basename(command.replace('\\', '/')), retCode['ErrorCode'], retCode['ReturnCode']))

        self.undeploy(srvname)

    def openPipe(self, s, tid, pipe, accessMask):
        pipeReady = False
        tries = 50

        while pipeReady is False and tries > 0:
            try:
                self.__smb.waitNamedPipe(tid, pipe)
                pipeReady = True
            except Exception, e:
                #traceback.print_exc()
                logger.error('Named pipe open error: %s' % str(e))
                tries -= 1
                time.sleep(2)

        if tries == 0:
            logger.error('Named pipe not ready, aborting')
            raise

        fid = self.__smb.openFile(tid, pipe, accessMask, creationOption=0x40, fileAttributes=0x80)

        return fid

class Pipes(Thread):
    def __init__(self, transport, pipe, permissions, share=None):
        Thread.__init__(self)
        self.server = 0
        self.transport = transport
        self.credentials = transport.get_credentials()
        self.tid = 0
        self.fid = 0
        self.share = share
        self.port = transport.get_dport()
        self.pipe = pipe
        self.permissions = permissions
        self.daemon = True

    def connectPipe(self):
        try:
            lock.acquire()
            self.server = SMBConnection('*SMBSERVER', self.transport.get_smb_connection().getRemoteHost(), sess_port = self.port)
            user, passwd, domain, lm, nt = self.credentials
            self.server.login(user, passwd, domain, lm, nt)
            lock.release()
            self.tid = self.server.connectTree('IPC$')

            self.server.waitNamedPipe(self.tid, self.pipe)
            self.fid = self.server.openFile(self.tid,self.pipe,self.permissions, creationOption = 0x40, fileAttributes = 0x80)
            self.server.setTimeout(1000000)
        except Exception, e:
            #traceback.print_exc()
            logger.error('Named pipe connection error: %s (%s)' % (str(e), self.__class__))

class RemoteStdOutPipe(Pipes):
    def __init__(self, transport, pipe, permisssions):
        Pipes.__init__(self, transport, pipe, permisssions)

    def run(self):
        self.connectPipe()

        while True:
            try:
                ans = self.server.readFile(self.tid,self.fid, 0, 1024)
            except:
                pass
            else:
                try:
                    global LastDataSent

                    if ans != LastDataSent:
                        sys.stdout.write(ans)
                        sys.stdout.flush()
                    else:
                        # Don't echo what I sent, and clear it up
                        LastDataSent = ''

                    # Just in case this got out of sync, i'm cleaning it up if there are more than 10 chars,
                    # it will give false positives tho.. we should find a better way to handle this.
                    if LastDataSent > 10:
                        LastDataSent = ''
                except:
                    pass

class RemoteStdErrPipe(Pipes):
    def __init__(self, transport, pipe, permisssions):
        Pipes.__init__(self, transport, pipe, permisssions)

    def run(self):
        self.connectPipe()

        while True:
            try:
                ans = self.server.readFile(self.tid, self.fid, 0, 1024)
            except:
                pass
            else:
                try:
                    sys.stderr.write(str(ans))
                    sys.stderr.flush()
                except:
                    pass

class RemoteShell(cmd.Cmd):
    def __init__(self, server, port, credentials, tid, fid, share):
        cmd.Cmd.__init__(self, False)
        self.prompt = '\x08'
        self.server = server
        self.tid = tid
        self.fid = fid
        self.credentials = credentials
        self.share = share
        self.port = port

    def cmdloop(self):
        try:
            cmd.Cmd.cmdloop(self)
        except SessionError, e:
            #traceback.print_exc()
            logger.error('SMB error: %s' % (e.getErrorString(), ))
        except NetBIOSTimeout, e:
            logger.error('SMB connection timed out')
        except keimpxError, e:
            logger.error(e)
        except KeyboardInterrupt, _:
            print
            logger.info('User aborted')
            self.do_exit('')
        except Exception, e:
            #traceback.print_exc()
            logger.error(str(e))

    def emptyline(self):
        self.send_data('\r\n')
        return

    def do_shell(self, command):
        process = Popen(command, shell=True, stdout=PIPE, stderr=STDOUT)
        stdout, _ = process.communicate()

        if stdout is not None:
            print stdout

        self.send_data('\r\n')

    def do_exit(self, line):
        self.send_data('exit\r\n')
        return

    def default(self, line=''):
        self.send_data('%s\r\n' % line)

    def send_data(self, data, hideOutput = True):
        if hideOutput is True:
            global LastDataSent
            LastDataSent = data
        else:
            LastDataSent = ''

        self.server.writeFile(self.tid, self.fid, data)

class RemoteStdInPipe(Pipes):
    def __init__(self, transport, pipe, permisssions, share=None):
        Pipes.__init__(self, transport, pipe, permisssions, share)

    def run(self):
        self.connectPipe()
        self.remote_shell = RemoteShell(self.server, self.port, self.credentials, self.tid, self.fid, self.share)
        self.remote_shell.cmdloop()
