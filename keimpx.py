#!/usr/bin/env python
# -*- coding: iso-8859-15 -*-
# -*- Mode: python -*-

'''
$Id$

keimpx is an open source tool, released under a modified version of Apache
License 1.1. It is developed in Python using CORE Impact's Impacket
library.

It can be used to quickly check for the usefulness of credentials across a
network over SMB.

Homepage:                   http://code.google.com/p/keimpx/wiki/Homepage
Usage:                      http://code.google.com/p/keimpx/wiki/Usage
Examples:                   http://code.google.com/p/keimpx/wiki/Examples
Frequently Asked Questions: http://code.google.com/p/keimpx/wiki/FAQ
Contributors:               http://code.google.com/p/keimpx/wiki/Contributors

License:

I provide this software under a slightly modified version of the
Apache Software License. The only changes to the document were the
replacement of "Apache" with "keimpx" and "Apache Software Foundation"
with "Bernardo Damele A. G.". Feel free to compare the resulting document
to the official Apache license.

The `Apache Software License' is an Open Source Initiative Approved
License.

The Apache Software License, Version 1.1
Modifications by Bernardo Damele A. G. (see above)

Copyright (c) 2009 Bernardo Damele A. G. <bernardo.damele@gmail.com>
All rights reserved.

This product includes software developed by CORE Security Technologies
(http://www.coresecurity.com/).

THIS SOFTWARE IS PROVIDED ``AS IS'' AND ANY EXPRESSED OR IMPLIED
WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES
OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
DISCLAIMED.  IN NO EVENT SHALL THE APACHE SOFTWARE FOUNDATION OR
ITS CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF
USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND
ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY,
OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT
OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
SUCH DAMAGE.
'''



__author__ = 'Bernardo Damele A. G. <bernardo.damele@gmail.com>'
__version__ = '0.1'


import binascii
import logging
import os
import re
import rlcompleter
import socket
import string
import sys
import threading
import time
import warnings

from optparse import OptionError
from optparse import OptionGroup
from optparse import OptionParser
from subprocess import mswindows
from subprocess import PIPE
from subprocess import Popen
from subprocess import STDOUT
from threading import Thread

try:
    from readline import *
    import readline as _rl

    have_readline = True
except ImportError:
    try:
        from pyreadline import *
        import pyreadline as _rl

        have_readline = True
    except ImportError:    
        have_readline = False

try:
    from impacket import smb
    from impacket.nmb import NetBIOSTimeout
    from impacket.dcerpc import dcerpc
    from impacket.dcerpc import transport
    from impacket.dcerpc import samr
    from impacket.dcerpc import svcctl
except ImportError:
    sys.stderr.write('You need to install Python Impacket library first\n')
    sys.exit(255)


added_credentials = set()
added_targets     = set()
credentials       = []
conf              = {}
domains           = []
pool_thread       = None
successes         = 0
targets           = []

logger         = logging.getLogger('logger')
logger_handler = logging.StreamHandler(sys.stdout)
formatter      = logging.Formatter('[%(asctime)s] [%(levelname)s] %(message)s', '%H:%M:%S')

logger_handler.setFormatter(formatter)
logger.addHandler(logger_handler)
logger.setLevel(logging.WARN)


class credentialsError(Exception):
    pass


class domainError(Exception):
    pass


class targetError(Exception):
    pass


class threadError(Exception):
    pass


class missingShare(Exception):
    pass


class CompleterNG(rlcompleter.Completer):
    def global_matches(self, text):
        matches = []
        n = len(text)

        for ns in [ self.namespace ]:
            for word in ns:
                if word[:n] == text:
                    matches.append(word)

        return matches


def autoCompletion():
    global have_readline

    if not have_readline:
        return

    completer = CompleterNG({
                              'help': None,
                              'info': None,
                              'verbosity': None,
                              'shares': None,
                              'use': None,
                              'cd': None,
                              'pwd': None,
                              'ls': None,
                              'cat': None,
                              'download': None,
                              'upload': None,
                              'mkdir': None,
                              'rm': None,
                              'rmdir': None,
                              'deploy': None,
                              'undeploy': None,
                              'users': None,
                              'domains': None,
                              'exit': None
                            })

    _rl.set_completer(completer.complete)
    _rl.parse_and_bind('tab: complete')


class SMBShell:
    def __init__(self, target, credentials):
        '''
        Initialize the object variables
        '''

        self.__target = target
        self.__dstip = self.__target.getHost()
        self.__dstport = self.__target.getPort()

        self.__user = credentials.getUser()
        self.__password = credentials.getPassword()
        self.__lmhash = credentials.getlmhash()
        self.__nthash = credentials.getnthash()
        self.__domain = credentials.getDomain()

        self.__dstname = '*SMBSERVER'
        self.__srcname = conf.name

        self.__timeout = 10

        self.smb = None
        self.tid = None
        self.pwd = ''
        self.share = None
        self.sharesList = []
        self.domainsList = []
        self.usersList = []


    def __local_exec(self, cmd):
        '''
        Execute a local command if the provided command is preceed by an
        exclamation mark
        '''

        process = Popen(cmd, shell=True, stdout=PIPE, stderr=STDOUT)
        stdout, _ = process.communicate()

        if stdout is not None:
            print stdout


    def __replace(self, value):
        return value.replace('/', '\\')


    def __check_share(self):
        if self.share is None or self.tid is None:
            raise missingShare, 'Share has not been specified'


    def eval(self, i=None):
        '''
        Evaluate the command provided via the command prompt
        '''

        if i is None:
            self.exit()

        elif i[0] == '!':
            self.__local_exec(i[1:])
            return

        l = string.split(i, ' ')
        cmd = l[0]

        try:
            f = SMBShell.__dict__[cmd]
            l[0] = self
            f(*l)

        except missingShare, _:
            logger.error('You first have to specify the share with \'use\' or \'shares\' command')

        except smb.SessionError, e:
            logger.error('SMB exception: %s' % str(e).split('code: ')[1])

        except Exception, e:
            logger.error('Exception: %s' % e)


    def run(self):
        '''
        Create a new SMB session with the provided login details and
        show the command prompt
        '''

        self.connect()
        logger.debug('Connection to host %s established' % self.__target.getIdentity())
        self.login()
        logger.debug('Logged in as %s' % self.__user)

        logger.info('type \'help\' for help menu')

        i = raw_input('# ')

        while i:
            self.eval(i)

            i = raw_input('# ')


    def help(self):
        '''
        Show the help menu
        '''

        print '''Generic options
===============
help - show this message
verbosity {level} - set verbosity level (0-2)
info - list system information
exit - terminates the SMB session and exit from the tool

Shares options
==============
shares - list available shares
use {sharename} - connect to an specific share
cd {path} - changes the current directory to {path}
pwd - shows current remote directory
ls {path} - lists all the files in the current directory
cat {file} - display content of the selected file
download {filename} - downloads the filename from the current path
upload {filename} - uploads the filename into the current path
mkdir {dirname} - creates the directory under the current path
rm {file} - removes the selected file
rmdir {dirname} - removes the directory under the current path

Services options
================
deploy {service name} {filename} [service args] - deploy remotely a service binary
undeploy {srvname} {filename} - undeploy remotely a service binary

Users options
=============
users [domain] - list users, optionally for a specific domain
domains - list domains to which the system is part of

Registry options (TODO)
================
regread {registry key} - read a registry key
regwrite {registry key} {registry value} - add a value to a registry key
regdelete {registry key} - delete a registry key
'''


    def verbosity(self, level):
        set_verbosity(level)


    def connect(self):
        '''
        Connect the SMB session
        '''

        self.__smb = smb.SMB(remote_name=self.__dstname, remote_host=self.__dstip, my_name=self.__srcname, sess_port=self.__dstport, timeout=self.__timeout)


    def login(self):
        '''
        Login over the SMB session
        '''

        try:
            self.__smb.login(self.__user, self.__password, self.__domain, self.__lmhash, self.__nthash)

        except socket.error, e:
            logger.warn('Connection to host %s failed (%s)' % (self.__dstip, e[1]))
            raise RuntimeError

        except smb.SessionError, e:
            logger.error('SMB exception: %s' % str(e).split('code: ')[1])
            raise RuntimeError


    def exit(self):
        '''
        Disconnect the SMB session
        '''

        self.__smb.logoff()
        sys.exit(0)


    def info(self):
        '''
        Display system information like operating system
        '''

        print 'Operating system: %s' % self.__smb.get_server_os()
        print 'Netbios name: %s' % self.__smb.get_server_name()
        print 'Domain: %s' % self.__smb.get_server_domain()
        print 'Time: %s' % self.__smb.get_server_time()


    def shares(self):
        '''
        List available shares and display a menu to select which share to
        connect to
        '''

        count = 1

        for share in self.__smb.list_shared():
            self.sharesList.append(share.get_name())
            print '[%d] %s (type: %s, comment: %s)' % (count, share.get_name(), share.get_type(), share.get_comment())
            count += 1

        msg = 'Which share do you want to connect to? (default 1) '
        limit = len(self.sharesList)
        choice = read_input(msg, limit)

        self.use(self.sharesList[choice-1])


    def use(self, sharename):
        '''
        Select the share to connect to
        '''

        self.share = sharename
        self.tid = self.__smb.tree_connect(sharename)
        self.pwd = ''


    def cd(self, path=None):
        '''
        Change the current path
        '''

        if path is None:
            self.pwd = ''
            return
        elif path == '.':
            return
        elif path == '..':
            sep = self.pwd.split('\\')
            self.pwd = '\\'.join(s for s in sep[:-1])
            return

        path = self.__replace(path)

        if path[0] == '\\':
           self.pwd = path
        else:
           self.pwd += '\\%s' % path


    def pwd(self):
        '''
        Display the current path
        '''

        print self.pwd


    def dir(self, path=None):
        '''
        Wrapper method to list files from the current/provided path
        '''

        self.ls(path)


    def ls(self, path=None):
        '''
        List files from the current/provided path
        '''

        self.__check_share()

        if path is None:
            pwd = '%s\\*' % self.pwd
        else:
            pwd = '%s\\%s\\*' % (self.pwd, self.__replace(path))

        for f in self.__smb.list_path(self.share, pwd):
            if f.is_directory() == 16:
                is_dir = '<DIR>'
            else:
                is_dir = '     '

            if f.get_filesize() == 0:
                filesize = '   '
            else:
                filesize = f.get_filesize()

            print '%s\t%s\t%s\t%s' % (time.ctime(float(f.get_mtime_epoch())), is_dir, filesize, f.get_longname())


    def cat(self, filename):
        '''
        Display a file content from the current path
        '''

        self.__check_share()

        filename = '%s\\%s' % (self.pwd, self.__replace(filename))
        self.fid = self.__smb.open(self.tid, filename, smb.SMB_O_OPEN, smb.SMB_ACCESS_READ)[0]

        offset = 0

        while 1:
            data = self.__smb.read(self.tid, self.fid, offset, 40000)

            print data

            if len(data) == 0:
                break

            offset += len(data)

        self.__smb.close(self.tid, self.fid)


    def download(self, filename):
        '''
        Download a file from the current path
        '''

        self.__check_share()

        fh = open(filename, 'wb')
        filename = '%s\\%s' % (self.pwd, self.__replace(filename))

        self.__smb.retr_file(self.share, filename, fh.write)
        fh.close()


    def upload(self, filename, share=None, destfile=None):
        '''
        Upload a file in the current path
        '''

        try:
            fp = open(filename, 'rb')
        except IOError:
            logger.error('Unable to open file \'%s\'' % filename)
            return

        if share is None:
            self.__check_share()
            share = self.share

        if destfile is None:
            destfile = '%s\\%s' % (self.pwd, self.__replace(filename))

        self.__smb.stor_file(share, destfile, fp.read)
        fp.close()


    def mkdir(self, path):
        '''
        Create a directory in the current share
        '''

        self.__check_share()

        path = '%s\\%s' % (self.pwd, self.__replace(path))
        self.__smb.mkdir(self.share, path)


    def rm(self, filename, share=None):
        '''
        Remove a file in the current share
        '''

        filename = '%s\\%s' % (self.pwd, self.__replace(filename))

        if share is None:
            self.__check_share()
            share = self.share

        self.__smb.remove(share, filename)

 
    def rmdir(self, path):
        '''
        Remove a directory in the current share
        '''

        self.__check_share()

        path = '%s\\%s' % (self.pwd, self.__replace(path))
        self.__smb.rmdir(self.share, path)


    def deploy(self, srvname, filename, srvargs='\x00'):
        '''
        Wrapper method to deploy a Windows service. It uploads the service
        executable to the file system, creates a service as 'Automatic'
        and starts it
        '''

        self.__service_bin_upload(filename)
        self.__service_connect()
        self.__service_create(srvname, filename)
        self.__service_start(srvname, srvargs)
        self.__service_disconnect()


    def undeploy(self, srvname, filename):
        '''
        Wrapper method to undeploy a Windows service. It removes the service
        executable from the file system and marks the service as 'Disabled'
        '''

        logger.warn('Reboot is needed to fully remove the service')

        self.__service_connect()
        self.__service_stop(srvname)
        self.__service_delete(srvname)
        self.__service_disconnect()
        self.__service_bin_remove(filename)


    def users(self, usrdomain=None):
        self.__samr_connect()
        self.__samr_users(usrdomain)
        self.__samr_disconnect()


    def domains(self):
        self.__samr_connect()
        self.__samr_domains()
        self.__samr_disconnect()


    def __smb_transport(self, named_pipe):
        '''
        Initiate a SMB connection on a specific named pipe
        '''

        self.trans = transport.SMBTransport(dstip=self.__dstip, dstport=self.__dstport, filename=named_pipe)
        self.trans.set_credentials(self.__user, self.__password, self.__lmhash, self.__nthash)

        try:
            self.trans.connect()

        except socket.error, e:
            logger.warn('Connection to host %s failed (%s)' % (self.__dstip, e[1]))
            raise RuntimeError

        except smb.SessionError, e:
            logger.warn('SMB exception: %s' % str(e).split('code: ')[1])
            raise RuntimeError


    def __service_connect(self):
        '''
        Connect to svcctl
        '''

        logger.info('Connecting to the SVCCTL named pipe')

        self.__smb_transport('svcctl')

        logger.debug('Binding on Services Control Manager (SCM) interface')
        self.__dce = dcerpc.DCERPC_v5(self.trans)
        self.__dce.bind(svcctl.MSRPC_UUID_SVCCTL)
        self.__svc = svcctl.DCERPCSvcCtl(self.__dce)

        logger.debug('Sending SVCCTL open SCM request')
        opensc = svcctl.SVCCTLOpenSCManagerHeader()
        opensc.set_machine_name('IMPACT')
        self.__dce.send(opensc)

        logger.debug('Parsing SVCCTL open SCM response')
        data = self.__dce.recv()

        resp = svcctl.SVCCTLRespOpenSCManagerHeader(data)
        self.rpcerror(resp.get_return_code())

        self.__mgr_handle = resp.get_context_handle()


    def __service_disconnect(self):
        '''
        Disconnect from svcctl
        '''

        logger.debug('Disconneting from the SVCCTL named pipe')

        if self.__mgr_handle:
            data = self.__svc.close_handle(self.__mgr_handle)
            self.rpcerror(data.get_return_code())

        self.__dce.disconnect()


    def __service_bin_upload(self, filename):
        '''
        Upload the service binary
        '''

        srvfilename = os.path.basename(filename)
        share = 'ADMIN$'

        logger.info('Uploading the service binary file \'%s\' to %s' % (srvfilename, share))

        self.upload(filename, share, srvfilename)


    def __service_bin_remove(self, filename):
        '''
        Remove the service binary
        '''

        srvfilename = os.path.basename(filename)

        logger.info('Removing the service binary file \'%s\'' % srvfilename)

        self.rm(srvfilename, share='ADMIN$')


    def __service_create(self, srvname, filename):
        '''
        Create the service
        '''

        srvfilename = os.path.basename(filename)

        logger.info('Creating the service \'%s\'' % srvname)

        data = self.__svc.create_service(self.__mgr_handle, srvname, '%%systemroot%%\\%s' % srvfilename)
        self.rpcerror(data.get_return_code())


    def __service_delete(self, srvname):
        '''
        Delete the service
        '''

        logger.info('Deleting the service \'%s\'' % srvname)

        resp = self.__svc.open_service(self.__mgr_handle, srvname)
        svc_handle = resp.get_context_handle()
        self.__svc.delete_service(svc_handle)


    def __service_start(self, srvname, srvargs):
        '''
        Start the service
        '''

        logger.info('Starting the service \'%s\'' % srvname)

        resp = self.__svc.open_service(self.__mgr_handle, srvname)
        svc_handle = resp.get_context_handle()

        data = self.__svc.start_service(svc_handle, srvargs)
        self.rpcerror(data.get_return_code())

        data = self.__svc.close_handle(svc_handle)
        self.rpcerror(data.get_return_code())


    def __service_stop(self, srvname):
        '''
        Stop the service
        '''

        logger.info('Stopping the service \'%s\'' % srvname)

        resp = self.__svc.open_service(self.__mgr_handle, srvname)
        svc_handle = resp.get_context_handle()

        data = self.__svc.stop_service(svc_handle)
        self.rpcerror(data.get_return_code())

        data = self.__svc.close_handle(svc_handle)
        self.rpcerror(data.get_return_code())


    def __samr_connect(self):
        '''
        Connect to samr
        '''

        logger.info('Connecting to the SAMR named pipe')

        self.__smb_transport('samr')

        logger.debug('Binding on Security Account Manager (SAM) interface')
        self.__dce = dcerpc.DCERPC_v5(self.trans)
        self.__dce.bind(samr.MSRPC_UUID_SAMR)
        self.__samr = samr.DCERPCSamr(self.__dce)

        resp = self.__samr.connect()
        self.rpcerror(resp.get_return_code())

        self.__mgr_handle = resp.get_context_handle()


    def __samr_disconnect(self):
        '''
        Disconnect from samr
        '''

        logger.debug('Disconneting from the SAMR named pipe')

        if self.__mgr_handle:
            data = self.__samr.closerequest(self.__mgr_handle)
            self.rpcerror(data.get_return_code())

        self.__dce.disconnect()


    def __samr_users(self, usrdomain=None):
        '''
        Enumerate users on the system
        '''

        self.__samr_domains(False)

        encoding = sys.getdefaultencoding()

        for domain in self.domainsList:
            domain_name = domain.get_name()

            if usrdomain is not None and usrdomain.upper() != domain_name.upper():
                continue

            logger.info('Looking up users in domain \'%s\'' % domain_name)

            resp = self.__samr.lookupdomain(self.__mgr_handle, domain)
            self.rpcerror(resp.get_return_code())

            resp = self.__samr.opendomain(self.__mgr_handle, resp.get_domain_sid())
            self.rpcerror(resp.get_return_code())

            self.__domain_context_handle = resp.get_context_handle()

            resp = self.__samr.enumusers(self.__domain_context_handle)
            self.rpcerror(resp.get_return_code())

            for user in resp.get_users().elements():
                uname = user.get_name().encode(encoding, 'replace')
                uid = user.get_id()

                r = self.__samr.openuser(self.__domain_context_handle, uid)
                logger.debug('Found user \'%s\' (UID: %d)' % (uname, uid))

                if r.get_return_code() == 0:
                    info = self.__samr.queryuserinfo(r.get_context_handle()).get_user_info()
                    entry = (uname, uid, info)
                    self.usersList.append(entry)
                    c = self.__samr.closerequest(r.get_context_handle())

        if self.usersList:
            num = len(self.usersList)

            if num == 1:
                logger.info('Enumerated one user')
            else:
                logger.info('Enumerated %d user' % num)
        else:
            logger.info('No users enumerated')

        for entry in self.usersList:
            user, uid, info = entry

            print user
            print '  User ID: %d' % uid
            print '  Group ID: %d' % info.get_group_id()
            print '  Enabled: %s' % ('False', 'True')[info.is_enabled()]

            try:
                print '  Logon count: %d' % info.get_logon_count()
            except ValueError:
                pass

            try:
                print '  Last Logon: %s' % info.get_logon_time()
            except ValueError:
                pass

            try:
                print '  Last Logoff: %s' % info.get_logoff_time()
            except ValueError:
                pass

            try:
                print '  Kickoff: %s' % info.get_kickoff_time()
            except ValueError:
                pass

            try:
                print '  Last password set: %s' % info.get_pwd_last_set()
            except ValueError:
                pass

            try:
                print '  Password can change: %s' % info.get_pwd_can_change()
            except ValueError:
                pass

            try:
                print '  Password must change: %s' % info.get_pwd_must_change()
            except ValueError:
                pass

            try:
                print '  Bad password count: %d' % info.get_bad_pwd_count()
            except ValueError:
                pass

            items = info.get_items()

            for i in samr.MSRPCUserInfo.ITEMS.keys():
                name = items[samr.MSRPCUserInfo.ITEMS[i]].get_name()
                name = name.encode(encoding, 'replace')

                if name:
                    print '  %s: %s' % (i, name)


    def __samr_domains(self, display=True):
        '''
        Enumerate domains to which the system is part of
        '''

        logger.info('Enumerating domains')

        resp = self.__samr.enumdomains(self.__mgr_handle)
        self.rpcerror(resp.get_return_code())

        domains = resp.get_domains().elements()

        if display is True:
            print 'Domains:'

        for domain in range(0, resp.get_entries_num()):
            domain = domains[domain]
            self.domainsList.append(domain)

            if display is True:
                print '  %s' % domain.get_name()


    def rpcerror(self, code):
        '''
        Check for an error in response packet
        '''

        if code in dcerpc.rpc_status_codes:
            logger.error('Error during negotiation: %s (%d)' % (dcerpc.rpc_status_codes[code], code))
            raise RuntimeError
        elif code != 0:
            logger.error('Unknown error during negotiation (%d)' % code)
            raise RuntimeError


class test_login(Thread):
    def __init__(self, target):
        Thread.__init__(self)

        self.__target = target
        self.__dstip = self.__target.getHost()
        self.__dstport = self.__target.getPort()
        self.__dstname = '*SMBSERVER'
        self.__srcname = conf.name
        self.__timeout = 10


    def connect(self):
        self.__smb = smb.SMB(remote_name=self.__dstname, remote_host=self.__dstip, my_name=self.__srcname, sess_port=self.__dstport, timeout=self.__timeout)


    def login(self, user, password, lmhash, nthash, domain):
        self.__smb.login(user, password, domain, lmhash, nthash)


    def logoff(self):
        self.__smb.logoff()


    def run(self):
        global credentials
        global successes

        try:
            logger.info('Attacking host %s' % self.__target.getIdentity())
            self.connect()
            logger.debug('Connection to host %s established' % self.__target.getIdentity())

            for credential in credentials:
                user, password, lmhash, nthash = credential.getCredentials()

                if password != '' or ( password == '' and lmhash == '' and nthash == ''):
                    password_str = password or 'BLANK'
                elif lmhash != '' and nthash != '':
                    password_str = '%s:%s' % (lmhash, nthash)

                for domain in domains:
                    status = False

                    if domain:
                        target_str = '%s:%s@%s' % (self.__dstip, self.__dstport, domain)
                    else:
                        target_str = '%s:%s' % (self.__dstip, self.__dstport)

                    try:
                        self.login(user, password, lmhash, nthash, domain)
                        self.logoff()

                        logger.info('Valid credentials on %s: %s/%s' % (target_str, user, password_str))

                        status = True
                        successes += 1

                    except smb.SessionError, e:
                        logger.info('Wrong credentials on %s: %s/%s (%s)' % (target_str, user, password_str, str(e).split('code: ')[1]))

                        status = str(e.get_error_code())

                    credential.addAnswer(self.__dstip, self.__dstport, domain, status)
                    self.__target.addAnswer(user, password, lmhash, nthash, domain, status)

                    if status is True:
                        break

            logger.info('Attack on host %s finished' % self.__target.getIdentity())

        except (socket.error, NetBIOSTimeout), e:
            logger.warn('Connection to host %s failed (%s)' % (self.__target.getIdentity(), e[1]))

        pool_thread.release()


class CredentialsStatus:
    def __init__(self, user, password, lmhash, nthash, domain, status):
        self.user = user
        self.password = password
        self.lmhash = lmhash
        self.nthash = nthash
        self.domain = domain
        self.status = status


    def getUser(self):
        return self.user


    def getPassword(self):
        return self.password


    def getlmhash(self):
        return self.lmhash


    def getnthash(self):
        return self.nthash    


    def getDomain(self):
        return self.domain


    def getStatus(self):
        return self.status


    def getIdentity(self):
        if self.lmhash != '' and self.nthash != '':
            return '%s/%s:%s' % (self.user, self.lmhash, self.nthash)
        elif self.user not in ( None, '' ):
            return '%s/%s' % (self.user, self.password or 'BLANK')


class TargetStatus:
    def __init__(self, host, port, domain, status):
        self.host = host
        self.port = port
        self.domain = domain
        self.status = status


    def getHost(self):
        return self.host


    def getPort(self):
        return self.port


    def getDomain(self):
        return self.domain


    def getStatus(self):
        return self.status


    def getIdentity(self):
        if self.domain:
            return '%s:%s@%s' % (self.host, self.port, self.domain)
        else:
            return '%s:%s' % (self.host, self.port)


class Credentials:
    def __init__(self, user, password='', lmhash='', nthash=''):
        self.user = user
        self.password = password
        self.lmhash = lmhash
        self.nthash = nthash

        # Targets where these credentials have been tested
        self.targets = []

        
    def getUser(self):
        return self.user


    def getPassword(self):
        return self.password


    def getlmhash(self):
        return self.lmhash


    def getnthash(self):
        return self.nthash


    def getIdentity(self):
        if self.lmhash != '' and self.nthash != '':
            return '%s/%s:%s' % (self.user, self.lmhash, self.nthash)
        elif self.user not in ( None, '' ):
            return '%s/%s' % (self.user, self.password or 'BLANK')


    def getCredentials(self):
        if self.password != '' or ( self.password == '' and self.lmhash == '' and self.nthash == ''):
            return self.user, self.password, '', ''
        elif self.lmhash != '' and self.nthash != '':
            return self.user, '', self.lmhash, self.nthash


    def addAnswer(self, host, port, domain, status):
        self.targets.append(TargetStatus(host, port, domain, status))


    def getResults(self, status=True):
        return_targets = []

        for target in self.targets:
            if target.getStatus() == status or status == '*':
                return_targets.append(target)

        return return_targets


class Target:
    def __init__(self, target, port):
        self.target = target
        self.port = port

        # Credentials tested on this target
        self.credentials = []


    def getHost(self):
        return self.target


    def getPort(self):
        return self.port


    def getIdentity(self):
        return '%s:%s' % (self.target, self.port)


    def addAnswer(self, user, password, lmhash, nthash, domain, status):
        self.credentials.append(CredentialsStatus(user, password, lmhash, nthash, domain, status))


    def getResults(self, status=True):
        return_credentials = []

        for credentials in self.credentials:
            if credentials.getStatus() == status or status == '*':
                return_credentials.append(credentials)

        return return_credentials


def read_input(msg, counter):
    while True:
        choice = raw_input(msg)

        if choice == '':
            choice = 1
            break
        elif choice.isdigit() and int(choice) >= 1 and int(choice) <= counter:
            choice = int(choice)
            break
        else:
            logger.warn('The choice must be a digit between 1 and %d' % counter)

    return choice


def remove_comments(lines):
    cleaned_lines = []

    for line in lines:
        # Ignore comment lines and blank ones
        if line.find('#') == 0 or line.isspace() or len(line) == 0:
            continue

        cleaned_lines.append(line)

    return cleaned_lines


def parse_domains_file(filename):
    try:
        fp = open(filename, 'r')
        file_lines = fp.read().splitlines()
        fp.close()

    except IOError, e:
        logger.error('Could not open domains file \'%s\'' % filename)
        return

    file_lines = remove_comments(file_lines)

    for line in file_lines:
        add_domain(line)


def add_domain(line):
    global domains

    try:
        local_domains = str(line).replace(' ', '').split(',')
    except domainError, _:
        logger.warn('Bad line in domains file \'%s\': %s' % (conf.domainsfile, line))
        return

    domains.extend(local_domains)

    logger.debug('Parsed domain(s) \'%s\'' % ', '.join([domain for domain in local_domains]))


def set_domains():
    global domains
    global conf

    logger.info('Loading domains')

    if conf.domain is not None:
        logger.debug('Loading domains from command line')
        add_domain(str(conf.domain))

    if conf.domainsfile is not None:
        logger.debug('Loading domains from file \'%s\'' % conf.list)
        parse_domains_file(conf.domainsfile)

    domains = list(set(domains))


def parse_credentials_file(filename):
    try:
        fp = open(filename, 'r')
        file_lines = fp.read().splitlines()
        fp.close()

    except IOError, e:
        logger.error('Could not open credentials file \'%s\'' % filename)
        return

    file_lines = remove_comments(file_lines)

    for line in file_lines:
        add_credentials(line=line)


def parse_credentials(credentials_line):
    fgdumpmatch = re.compile('^(\S*?):.*?:(\S*?):(\S*?):.*?:.*?:')
    fgdump = fgdumpmatch.match(credentials_line)

    emptypassmatch = re.compile('^(\S*?):.*?:NO\sPASSWORD.+')
    empty = emptypassmatch.match(credentials_line)

    cainmatch = re.compile('^(\S*?):.*?:.*?:(\S*?):(\S*?)$')
    cain = cainmatch.match(credentials_line)

    plaintextpassmatch = re.compile('^(\S+?)\s(\S+?)$')
    plain = plaintextpassmatch.match(credentials_line)

    # Credentials with hashes (pwdump/pwdumpx/fgdump/pass-the-hash output format)
    if fgdump:
        try:
            binascii.a2b_hex(fgdump.group(2))
            binascii.a2b_hex(fgdump.group(3))

            return fgdump.group(1), '', fgdump.group(2), fgdump.group(3)
        except:
            raise credentialsError, 'credentials error'

    # Credentials with empty password (pwdump/pwdumpx/fgdump output format)
    elif empty:
        return empty.group(1), '', '', ''

    # Credentials with hashes (cain/l0phtcrack output format)
    elif cain:
        try:
            binascii.a2b_hex(cain.group(2))
            binascii.a2b_hex(cain.group(3))

            return cain.group(1), '', cain.group(2), cain.group(3)
        except:
            raise credentialsError, 'credentials error'

    # Credentials with password (added by user manually divided by a space)
    elif plain:
        return plain.group(1), plain.group(2), '', ''

    else:
        raise credentialsError, 'credentials error'


def add_credentials(user=None, password='', lmhash='', nthash='', line=None):
    global added_credentials
    global credentials

    if line is not None:
        try:
            user, password, lmhash, nthash = parse_credentials(line)
        except credentialsError, _:
            logger.warn('Bad line in credentials file \'%s\': %s' % (conf.credsfile, line))
            return

    if (user, password, lmhash, nthash) in added_credentials:
        return
    elif user not in ( None, '' ):
        added_credentials.add((user, password, lmhash, nthash))

        credential = Credentials(user, password, lmhash, nthash)
        credentials.append(credential)

        logger.debug('Parsed credentials \'%s\'' % credential.getIdentity())


def set_credentials():
    global conf

    logger.info('Loading credentials')

    if conf.user is not None:
        logger.debug('Loading credentials from command line')
        add_credentials(conf.user, conf.password or '', conf.lmhash or '', conf.nthash or '')

    if conf.credsfile is not None:
        logger.debug('Loading credentials from file \'%s\'' % conf.credsfile)
        parse_credentials_file(conf.credsfile)


def parse_targets_file(filename):
    try:
        fp = open(filename, 'r')
        file_lines = fp.read().splitlines()
        fp.close()

    except IOError, e:
        logger.error('Could not open targets file \'%s\'' % filename)
        return

    file_lines = remove_comments(file_lines)

    for line in file_lines:
        add_target(line)


def parse_target(target_line):
    targetmatch = re.compile('^([A-z0-9\.]+)(:(\d+))?')
    h = targetmatch.match(target_line)

    if h and h.group(3):
        host = h.group(1)
        port = h.group(3)

        if port.isdigit() and int(port) > 1 and int(port) < 65535:
            return host, int(port)
        else:
            return host, conf.port

    elif h:
        host = h.group(1)

        return host, conf.port

    else:
        raise targetError, 'target error'


def add_target(line):
    global added_targets
    global targets

    try:
        host, port = parse_target(line)
    except targetError, _:
        logger.warn('Bad line in targets file \'%s\': %s' % (conf.list, line))
        return

    if (host, port) in added_targets:
        return
    else:
        added_targets.add((host, port))

        target = Target(host, port)
        targets.append(target)

        logger.debug('Parsed target \'%s\'' % target.getIdentity())


def set_targets():
    global conf
    global targets

    logger.info('Loading targets')

    if conf.target is not None:
        logger.debug('Loading targets from command line')
        add_target(str(conf.target))

    if conf.list is not None:
        logger.debug('Loading targets from file \'%s\'' % conf.list)
        parse_targets_file(conf.list)


def set_verbosity(level=None):
    if level is not None:
        conf.verbose = int(level)

    if conf.verbose is None:
        conf.verbose = 0

    conf.verbose = int(conf.verbose)

    if conf.verbose == 1:
        logger.setLevel(logging.INFO)
    elif conf.verbose > 1:
        conf.verbose = 2
        logger.setLevel(logging.DEBUG)


def check_conf():
    global conf

    set_verbosity()

    if conf.name is None:
        conf.name = socket.gethostname()

    conf.name = str(conf.name)

    if conf.port is None:
        conf.port = 445

    logger.debug('Using \'%s\' as local hostname' % conf.name)

    if conf.threads < 3:
        conf.threads = 3
        logger.warn('Forcing number of threads to 3')

    set_targets()
    set_credentials()
    set_domains()


def cmdline_parser():
    '''
    This function parses the command line parameters and arguments
    '''

    usage = '%s [options]' % sys.argv[0]
    parser = OptionParser(usage=usage, version=__version__)

    try:
        parser.add_option('-v', dest='verbose', type='int', default=0,
                          help='Verbosity level: 0-2 (default 0)')

        parser.add_option('-t', dest='target', help='Target address')

        parser.add_option('-l', dest='list', help='File with list of targets')

        parser.add_option('-U', dest='user', help='User')

        parser.add_option('-P', dest='password', help='Password')

        parser.add_option('--nt', dest='nthash', help='NT hash')

        parser.add_option('--lm', dest='lmhash', help='LM hash')

        parser.add_option('-c', dest='credsfile', help='File with list of credentials')

        parser.add_option('-D', dest='domain', help='Domain')

        parser.add_option('-d', dest='domainsfile', help='File with list of domains')

        parser.add_option('-p', dest='port', type='int', default=445,
                           help='SMB port: 139 or 445 (default 445)')

        parser.add_option('-n', dest='name', help='Local hostname')

        parser.add_option('--threads', dest='threads', type='int', default=10,
                          help='Maximum simultaneous connections (default 10)')

        (args, _) = parser.parse_args()

        if not args.target and not args.list:
            errMsg  = 'missing a mandatory parameter (-t or -l), '
            errMsg += '-h for help'
            parser.error(errMsg)

        return args
    except (OptionError, TypeError), e:
        parser.error(e)

    debugMsg = 'Parsing command line'
    logger.debug(debugMsg)


def banner():
    print '''
    keimpx %s
    by %s
    ''' % (__version__, __author__)


def main():
    global credentials
    global conf
    global domains
    global pool_thread
    global targets
    global have_readline

    banner()
    conf = cmdline_parser()
    check_conf()

    if len(targets) < 1:
        logger.error('No valid targets loaded')
        sys.exit(1)

    logger.info('Loaded %s unique targets' % len(targets))

    if len(credentials) < 1:
        logger.error('No valid credentials loaded')
        sys.exit(1)

    logger.info('Loaded %s unique credentials' % len(credentials))

    if len(domains) == 0:
        logger.info('No domains specified, using NULL domain')
        domains.append('')
    elif len(domains) > 0:
        logger.info('Loaded %s unique domains' % len(domains))

    pool_thread = threading.BoundedSemaphore(conf.threads)

    try:
        for target in targets:
            pool_thread.acquire()
            current = test_login(target)
            current.start()

        while (threading.activeCount() > 1):
            a = 'Caughtit'
            pass

    except KeyboardInterrupt:
        try:
            logger.warn('Test interrupted, waiting for threads to finish')

            while (threading.activeCount() > 1):
                a = 'Caughtit'
                pass

        except KeyboardInterrupt:
            logger.info('User aborted')
            sys.exit(1)

    if successes == 0:
        print '\nNo credentials worked on any target\n'
        sys.exit(1)

    print '\nThe credentials worked in total %d times\n' % successes
    print 'TARGET SORTED RESULTS:\n'

    for target in targets:
        results = target.getResults()

        if len(results):
            print target.getIdentity()

            for result in results:
                print '  %s' % result.getIdentity()

            print

    print '\nUSER SORTED RESULTS:\n'

    for credential in credentials:
        results = credential.getResults()

        if len(results):
            print credential.getIdentity()

            for result in results:
                print '  %s' % result.getIdentity()

            print

    msg = 'Do you want to get a shell from any of the targets? [Y/n] '
    choice = raw_input(msg)

    if choice and choice[0].lower() != 'y':
        return

    counter = 0
    targets_dict = {}

    msg = 'Which target do you want to connect to?'

    for target in targets:
        results = target.getResults()

        if len(results):
            counter += 1
            msg += '\n[%d] %s' % (counter, target.getIdentity())
            targets_dict[counter] = (target, results)

    msg += '\n> '

    choice = read_input(msg, counter)
    target, credentials = targets_dict[int(choice)]
    counter = 0
    credentials_dict = {}

    msg = 'Which credentials do you want to use to connect?'

    for credential in credentials:
        counter += 1
        msg += '\n[%d] %s' % (counter, credential.getIdentity())
        credentials_dict[counter] = credential

    msg += '\n> '

    choice = read_input(msg, counter)
    credentials = credentials_dict[int(choice)]

    if mswindows is True and have_readline:
        try:
            _outputfile = _rl.GetOutputFile()
        except AttributeError:
            debugMsg  = 'Failed GetOutputFile when using platform\'s '
            debugMsg += 'readline library'
            logger.debug(debugMsg)

            have_readline = False

    uses_libedit = False

    if sys.platform.lower() == 'darwin' and have_readline:
        import commands

        (status, result) = commands.getstatusoutput( 'otool -L %s | grep libedit' % _rl.__file__ )

        if status == 0 and len(result) > 0:
            _rl.parse_and_bind('bind ^I rl_complete')

            debugMsg  = 'Leopard libedit detected when using platform\'s '
            debugMsg += 'readline library'
            logger.debug(debugMsg)

            uses_libedit = True

    if have_readline:
        try:
            _rl.clear_history
        except AttributeError:
            def clear_history():
                pass

            _rl.clear_history = clear_history

    autoCompletion()

    try:
        shell = SMBShell(target, credentials)
        shell.run()
    except RuntimeError:
        sys.exit(255)
    except KeyboardInterrupt:
        print 'Bye bye!'
        sys.exit(0)


if __name__ == '__main__':
    print 'This product includes software developed by CORE Security Technologies'
    print '(http://www.coresecurity.com), Python Impacket library'

    warnings.filterwarnings(action='ignore', category=DeprecationWarning)
    main()

    sys.exit(0)
