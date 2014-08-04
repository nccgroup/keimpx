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

import os
import re

from lib.common import *
from lib.interactiveshell import InteractiveShell
from lib.smbshell import SMBShell

added_credentials = set()
added_targets = set()
conf = {}
credentials = []
domains = []
pool_thread = None
successes = 0
targets = []
commands = []
stop_threads = [False]

if hasattr(sys, 'frozen'):
    keimpx_path = os.path.dirname(unicode(sys.executable, sys.getfilesystemencoding()))
else:
    keimpx_path = os.path.dirname(os.path.realpath(__file__))

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

    def check_admin(self):
        try:
            self.__trans = transport.SMBTransport(dstip=self.__dstip, dstport=self.__dstport, filename='svcctl', smb_connection=self.smb)
            self.__trans.connect()
            self.__dce = self.__trans.get_dce_rpc()
            self.__dce.bind(scmr.MSRPC_UUID_SCMR)
            self.__resp = scmr.hROpenSCManagerW(self.__dce, dwDesiredAccess=scmr.SC_MANAGER_CREATE_SERVICE)
            self.__mgr_handle = self.__resp['lpScHandle']
            scmr.hRCloseServiceHandle(self.__dce, self.__mgr_handle)
            self.__dce.disconnect()
            return True
        except rpcrt.DCERPCException, e:
            pass
        except Exception, e:
            logger.error('Check admin error: %s' % str(e))

        return False

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
                    if stop_threads[0]:
                        break

                    status = False
                    error_code = None
                    is_admin = None

                    if domain:
                        user_str = '%s\%s' % (domain, user)
                    else:
                        user_str = user

                    try:
                        self.connect()
                        self.login(user, password, lmhash, nthash, domain)

                        if self.smb.isGuestSession() > 0:
                            logger.warn('%s allows guest sessions with any credentials, skipping further login attempts' % self.__target_id)
                            return
                        else:
                            is_admin = self.check_admin()

                            if self.smb.getServerDomain().upper() != domain.upper() and self.smb.getServerName().upper() != domain.upper():
                                domain = ''
                                user_str = user

                            logger.info('Successful login for %s with %s on %s %s' % (user_str, password_str, self.__target_id, "(admin user)" if is_admin else ""))

                        self.logoff()

                        status = True
                        successes += 1
                    except SessionError, e:
                        logger.debug('Failed login for %s with %s on %s %s' % (user_str, password_str, self.__target_id, e.getErrorString()))
                        error_code = e.getErrorCode()

                    credential.addTarget(self.__dstip, self.__dstport, domain, status, error_code, is_admin)
                    self.__target.addCredential(user, password, lmhash, nthash, domain, status, error_code, is_admin)

                    if status is True:
                        break

            logger.info('Assessment on host %s finished' % self.__target.getIdentity())
        except (socket.error, socket.herror, socket.gaierror, socket.timeout, NetBIOSTimeout), e:
            if not stop_threads[0]:
                logger.warn('Connection to host %s failed (%s)' % (self.__target.getIdentity(), str(e)))

        pool_thread.release()

class CredentialsTarget:
    def __init__(self, host, port, domain, status, error_code, is_admin):
        self.host = host
        self.port = port
        self.domain = domain
        self.status = status
        self.error_code = error_code
        self.is_admin = is_admin

    def getHost(self):
        return self.host

    def getPort(self):
        return self.port

    def getStatus(self):
        return self.status

    def isAdmin(self):
        return self.is_admin

    def getIdentity(self):
        if self.domain:
            return '%s:%s@%s %s' % (self.host, self.port, self.domain, '(admin user)' if self.isAdmin() else '')
        else:
            return '%s:%s %s' % (self.host, self.port, '(admin user)' if self.isAdmin() else '')

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

    def addTarget(self, host, port, domain, status, error_code, is_admin):
        self.tested_targets.append(CredentialsTarget(host, port, domain, status, error_code, is_admin))

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
    def __init__(self, user, password, lmhash, nthash, domain, status, error_code, is_admin):
        self.user = user
        self.password = password
        self.lmhash = lmhash
        self.nthash = nthash
        self.domain = domain
        self.status = status
        self.error_code = error_code
        self.is_admin = is_admin

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

    def isAdmin(self):
        return self.is_admin

    def getIdentity(self):
        if self.domain:
            _ = '%s\%s' % (self.domain, self.user)
        else:
            _ = self.user

        if self.lmhash != '' and self.nthash != '':
            return '%s/%s:%s %s' % (_, self.lmhash, self.nthash, '(admin user)' if self.isAdmin() else '')
        else:
            return '%s/%s %s' % (_, self.password or 'BLANK', '(admin user)' if self.isAdmin() else '')

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

    def addCredential(self, user, password, lmhash, nthash, domain, status, error_code, is_admin):
        self.tested_credentials.append(TargetCredentials(user, password, lmhash, nthash, domain, status, error_code, is_admin))

    def getCredentials(self, valid_only=False):
        _ = []

        for tested_credential in self.tested_credentials:
            if (valid_only and tested_credential.getStatus() is True) \
                or not valid_only:
                _.append(tested_credential)

        return _

    def getValidCredentials(self):
        return self.getCredentials(True)

def add_command(cmd):
    global commands

    #if cmd is not None and len(cmd) > 0 and cmd not in commands:
    if cmd is not None and len(cmd) > 0:
        commands.append(cmd)

def parse_list_file(filename):
    global commands

    commands = []

    try:
        fp = open(filename, 'rb')
        file_lines = fp.read().splitlines()
        fp.close()
    except IOError, e:
        logger.error('Could not open commands file %s' % filename)
        return

    file_lines = remove_comments(file_lines)

    for line in file_lines:
        add_command(line)

def get_admin_credentials(target):
    for credentials in target.getValidCredentials():
        if credentials.isAdmin():
            return credentials

    return False

def oscmdlist():
    parse_list_file(conf.oscmdlist)
    targets_tuple = ()

    for target in targets:
        admin_credentials = None

        if len(target.getValidCredentials()) == 0:
            continue
        else:
            admin_credentials = get_admin_credentials(target)

        if admin_credentials is False:
            admin_credentials = target.getValidCredentials()[0]
            logger.warn('No admin user identified for target %s, some commands will not work' % target.getIdentity())

        logger.info('Executing OS commands on %s with user %s' % (target.getIdentity(), admin_credentials.getUser()))
        smb_shell = SMBShell(target, admin_credentials, conf.name)

        if len(commands) > 0:
            logger.info('Executing OS commands from provided file')

            for command in commands:
                print 'OS command \'%s\' output:' % command

                try:
                    smb_shell.svcexec(command, 'SHARE')
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
                    smb_shell.do_exit('')
                except Exception, e:
                    #traceback.print_exc()
                    logger.error(str(e))

                print '----------8<----------'

def smbcmdlist():
    parse_list_file(conf.smbcmdlist)
    targets_tuple = ()

    for target in targets:
        if len(target.getValidCredentials()) == 0:
            continue
        else:
            admin_credentials = get_admin_credentials(target)

        if admin_credentials is False:
            admin_credentials = target.getValidCredentials()[0]
            logger.warn('No admin user identified for target %s, some commands will not work' % target.getIdentity())

        logger.info('Executing SMB commands on %s with user %s' % (target.getIdentity(), admin_credentials.getUser()))
        shell = InteractiveShell(target, admin_credentials, conf.name)

        if len(commands) > 0:
            logger.info('Executing SMB commands from provided file')

            for command in commands:
                print 'SMB command \'%s\' output:' % command

                try:
                    shell.onecmd(command)
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
                    shell.do_exit('')
                except Exception, e:
                    #traceback.print_exc()
                    logger.error(str(e))

                print '----------8<----------'

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

    for d in _:
        d = d.upper().split('.')[0]
        domains.append(d)

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

    fgdumpmatch = re.compile('^(\S+?):(.*?:?)([0-9a-fA-F]{32}):([0-9a-fA-F]{32}):.*?:.*?:\s*$')
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
            binascii.a2b_hex(fgdump.group(3))
            binascii.a2b_hex(fgdump.group(4))

            return fgdump.group(1), '', fgdump.group(3), fgdump.group(4)
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

            if user.count('\\') == 1:
                _, user = user.split('\\')
                add_domain(_)
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

def addr_to_int(value):
    _ = value.split('.')
    return (long(_[0]) << 24) + (long(_[1]) << 16) + (long(_[2]) << 8) + long(_[3])

def int_to_addr(value):
    return '.'.join(str(value >> n & 0xFF) for n in (24, 16, 8, 0))

def set_targets():
    logger.info('Loading targets')

    if conf.target is not None:
        if '/' not in conf.target:
            logger.debug('Loading targets from command line')
            add_target(conf.target)
        else:
            address, mask = re.search(r"([\d.]+)/(\d+)", conf.target).groups()
            logger.debug('Expanding targets from command line')
            start_int = addr_to_int(address) & ~((1 << 32 - int(mask)) - 1)
            end_int = start_int | ((1 << 32 - int(mask)) - 1)
            for _ in xrange(start_int, end_int):
                add_target(int_to_addr(_))

    if conf.list is not None:
        logger.debug('Loading targets from file %s' % conf.list)
        parse_targets_file(conf.list)

    if len(targets) < 1:
        logger.error('No valid targets loaded')
        sys.exit(1)

    logger.info('Loaded %s unique target%s' % (len(targets), 's' if len(targets) > 1 else ''))

def check_conf():
    global conf

    set_verbosity(conf.verbose)

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
                          help='Batch mode: do not prompt for an interactive SMB shell')

        parser.add_option('-x', dest='smbcmdlist', help='Execute a list of SMB '
                          'commands against all hosts')

        parser.add_option('-X', dest='oscmdlist', help='Execute a list of OS '
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
            current.daemon = True
            current.start()

        while (threading.activeCount() > 1):
            a = 'Caughtit'
            pass

    except KeyboardInterrupt:
        print
        try:
            logger.warn('Test interrupted')
            a = 'Caughtit'
            stop_threads[0] = True
        except KeyboardInterrupt:
            print
            logger.info('User aborted')
            os._exit(1)

    if successes == 0:
        print '\nNo credentials worked on any target\n'
        os._exit(0)

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

    if conf.smbcmdlist is not None:
        smbcmdlist()

    if conf.oscmdlist is not None:
        oscmdlist()

    if conf.batch or conf.smbcmdlist or conf.oscmdlist:
        return

    while True:
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
            shell = InteractiveShell(user_target, user_credentials, conf.name)
            shell.cmdloop()
        except RuntimeError, e:
            logger.error('Runtime error: %s' % str(e))
        except Exception, _:
            #traceback.print_exc()
            pass

if __name__ == '__main__':
    warnings.filterwarnings(action='ignore', category=DeprecationWarning)

    try:
        main()
    except KeyboardInterrupt:
        print
        logger.info('User aborted')
        os._exit(1)

    os._exit(0)
