#!/usr/bin/env python
# -*- coding: iso-8859-15 -*-
# -*- Mode: python -*-

'''
keimpx is an open source tool, released under the Apache
License 2.0. It is developed in Python using SecureAuth Corporations's
Impacket library, https://github.com/SecureAuthCorp/impacket.

It can be used to quickly check for the usefulness of credentials across a
network over SMB.

Homepage:                   https://nccgroup.github.io/keimpx/
Usage:                      https://github.com/nccgroup/keimpx#usage
Examples:                   https://github.com/nccgroup/keimpx/wiki/Examples
Frequently Asked Questions: https://github.com/nccgroup/keimpx/wiki/FAQ
Contributors:               https://github.com/nccgroup/keimpx#contributors

License:

Copyright 2009-2020 Bernardo Damele A. G. bernardo.damele@gmail.com

Licensed under the Apache License, Version 2.0 (the "License"); you may not use this file except in compliance with the
License. You may obtain a copy of the License at

http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software distributed under the License is distributed on an 
"AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the License for the 
specific language governing permissions and limitations under the License.
'''

from __future__ import print_function

__author__ = 'Bernardo Damele A. G. <bernardo.damele@gmail.com>'
__version__ = '0.6-dev'

import binascii
import os
import re
import socket
import sys
import threading
import warnings
from optparse import OptionError, OptionParser
from threading import Thread

from six.moves import input as input
from six.moves import range as range

from lib.common import remove_comments, set_verbosity, read_input
from lib.exceptions import keimpxError, credentialsError, targetError
from lib.interactiveshell import InteractiveShell
from lib.logger import logger
from lib.smbshell import SMBShell

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
    from impacket.nmb import NetBIOSTimeout
    from impacket.dcerpc.v5 import rpcrt
    from impacket.dcerpc.v5 import scmr
    from impacket.dcerpc.v5 import transport
    from impacket.smbconnection import SMBConnection, SessionError
except ImportError:
    sys.stderr.write('keimpx: Impacket import error')
    sys.stderr.write(
        'keimpx: Impacket by SecureAuth Corporation is required for this tool to work. Please download it using:'
        '\npip: pip install -r requirements.txt\nOr through your package manager:\npython-impacket.')
    sys.exit(255)

# Python 2: unicode is a built-in; Python 3: unicode built-in replaced by str
try:
    unicode
except NameError:
    unicode = str

conf = {}
pool_thread = None
successes = 0
stop_threads = [False]

if hasattr(sys, 'frozen'):
    keimpx_path = os.path.dirname(unicode(sys.executable))
else:
    keimpx_path = os.path.dirname(os.path.realpath(__file__))


class test_login(Thread):
    def __init__(self, target):
        Thread.__init__(self)

        self.__target = target
        self.__credentials = self.__target.get_credentials()
        self.__domains = self.__target.get_domains()
        self.__dstip = self.__target.get_host()
        self.__dstport = self.__target.get_port()
        self.__target_id = self.__target.get_identity()
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
            self.__trans = transport.SMBTransport(remoteName=self.__dstip, dstport=self.__dstport, filename='svcctl',
                                                  smb_connection=self.smb, remote_host=self.__dstip)
            self.__trans.connect()
            self.__dce = self.__trans.get_dce_rpc()
            self.__dce.bind(scmr.MSRPC_UUID_SCMR)
            self.__resp = scmr.hROpenSCManagerW(self.__dce, dwDesiredAccess=scmr.SC_MANAGER_CREATE_SERVICE)
            self.__mgr_handle = self.__resp['lpScHandle']
            scmr.hRCloseServiceHandle(self.__dce, self.__mgr_handle)
            self.__dce.disconnect()
            return True
        except rpcrt.DCERPCException as e:
            pass
        except Exception as e:
            logger.error('Check admin error: %s' % str(e))

        return False

    def run(self):
        global pool_thread
        global successes

        try:
            logger.info('Assessing host %s' % self.__target_id)

            for credential in self.__credentials:
                user, password, lmhash, nthash = credential.get_credential()
                password_str = None

                if password != '' or (password == '' and lmhash == '' and nthash == ''):
                    password_str = password or 'BLANK'
                elif lmhash != '' and nthash != '':
                    password_str = '%s:%s' % (lmhash, nthash)
                for domain in self.__domains:
                    if stop_threads[0]:
                        break

                    status = False
                    error_code = None
                    is_admin = None

                    if domain:
                        user_str = '%s\\%s' % (domain, user)
                    else:
                        user_str = user

                    try:
                        self.connect()
                        self.login(user, password, lmhash, nthash, domain)

                        if self.smb.isGuestSession() > 0:
                            logger.warn(
                                '%s allows guest sessions with any credentials, skipping further login attempts'
                                % self.__target_id)
                            return
                        else:
                            credential.is_admin = self.check_admin()

                            if (self.smb.getServerDomain().upper() != domain.upper()
                                    and self.smb.getServerName().upper() != domain.upper()):
                                domain = ''
                                user_str = user
                                credential.domain = domain

                            logger.info('Successful login for %s with %s on %s %s'
                                        % (user_str, password_str, self.__target_id,
                                           "(admin user)" if is_admin else ""))

                        self.logoff()

                        status = True
                        successes += 1
                        credential.is_valid = True

                    except SessionError as e:
                        logger.debug('Failed login for %s with %s on %s %s' % (
                            user_str, password_str, self.__target_id, e.getErrorString()))
                        error_code = e.getErrorCode()
                        if e.getErrorString()[0] is "STATUS_PASSWORD_MUST_CHANGE":
                            credential.is_valid = True
                            credential.password_change_required = True
                            status = True
                        elif e.getErrorString()[0] is "STATUS_ACCOUNT_LOCKED_OUT":
                            credential.is_valid = True
                            credential.is_locked_out = True
                            status = True
                        elif e.getErrorString()[0] is "STATUS_ACCOUNT_DISABLED":
                            credential.is_valid = True
                            credential.account_disabled = True
                            status = True
                        elif e.getErrorString()[0] is "STATUS_INVALID_LOGON_HOURS":
                            credential.is_valid = True
                            credential.outside_logon_hours = True
                            status = True
                        else:
                            credential.is_valid = False

                    if status is True:
                        break

            logger.info('Assessment on host %s finished' % self.__target.get_identity())
        except (socket.error, socket.herror, socket.gaierror, socket.timeout, NetBIOSTimeout) as e:
            if not stop_threads[0]:
                logger.warn('Connection to host %s failed (%s)' % (self.__target.get_identity(), str(e)))

        self.__target.update_credentials(self.__credentials)
        pool_thread.release()


class Credential:
    def __init__(self, user, password='', lmhash='', nthash='', domain='', account_status='', is_admin=False,
                 is_locked_out=False, password_change_required=False, account_disabled=False,
                 outside_logon_hours=False, is_valid=False):
        self.user = user
        self.password = password
        self.lmhash = lmhash
        self.nthash = nthash
        self.domain = domain
        self.is_admin = is_admin
        self.account_status = account_status
        self.is_locked_out = is_locked_out
        self.password_change_required = password_change_required
        self.account_disabled = account_disabled
        self.outside_logon_hours = outside_logon_hours
        self.is_valid = is_valid

    def get_user(self):
        return self.user

    def get_password(self):
        return self.password

    def get_domain(self):
        return self.domain

    def get_lm_hash(self):
        return self.lmhash

    def get_nt_hash(self):
        return self.nthash

    def get_is_admin(self):
        return self.is_admin

    def get_account_status(self):
        return self.account_status

    def get_is_locked_out(self):
        return self.is_locked_out

    def get_password_change_required(self):
        return self.password_change_required

    def get_is_valid(self):
        return self.is_valid

    def get_identity(self, account_details=True):
        identity = ""

        if self.lmhash != '' and self.nthash != '':
            if self.domain != '':
                identity = '%s\\%s/%s:%s' % (self.domain, self.user, self.lmhash, self.nthash)
            else:
                identity = '%s/%s:%s' % (self.user, self.lmhash, self.nthash)
        else:
            if self.domain != '':
                identity = '%s\\%s/%s' % (self.domain, self.user, self.password or 'BLANK')
            else:
                identity = '%s/%s' % (self.user, self.password or 'BLANK')

        if self.is_admin and account_details:
            identity += " (Administrator)"
        if self.is_locked_out and account_details:
            identity += " (Locked out)"
        if self.account_disabled and account_details:
            identity += " (Account disabled)"
        if self.password_change_required and account_details:
            identity += " (Password change required)"
        if self.outside_logon_hours and account_details:
            identity += " (Outside logon hours)"

        return identity

    def get_credential(self):
        if self.lmhash != '' and self.nthash != '':
            return self.user, self.password, self.lmhash, self.nthash
        else:
            return self.user, self.password, '', ''


class Target:
    def __init__(self, host, port):
        self.host = host
        self.port = int(port)

        self.credentials = []
        self.domains = []

    def get_host(self):
        return self.host

    def get_port(self):
        return self.port

    def get_identity(self):
        return '%s:%d' % (self.host, self.port)

    def add_credential(self, credential):
        self.credentials.append(credential)

    def update_credentials(self, credentials):
        self.credentials = None
        self.credentials = credentials

    def update_domains(self, domains):
        self.domains = domains

    def get_domains(self):
        return self.domains

    def get_credentials(self):
        return self.credentials

    def get_valid_credentials(self):
        valid_credentials = []
        for credential in self.credentials:
            if credential.get_is_valid() is True:
                valid_credentials.append(credential)
        return valid_credentials


def add_command(cmd):
    # if cmd is not None and len(cmd) > 0 and cmd not in commands:
    if cmd is not None and len(cmd) > 0:
        return cmd


def parse_list_file(filename):
    commands = []

    try:
        fp = open(filename, 'r')
        file_lines = fp.read().splitlines()
        fp.close()
    except IOError as _:
        logger.error('Could not open commands file %s' % filename)
        return

    file_lines = remove_comments(file_lines)

    for line in file_lines:
        commands.append(add_command(line))

    return commands


def get_admin_credentials(target):
    valid_credentials = target.get_valid_credentials()
    admin_credentials = []
    for credential in valid_credentials:
        if credential.get_is_admin() is True:
            admin_credentials.append(credential)

    if len(admin_credentials) > 0:
        return admin_credentials
    else:
        return False


def os_cmd_list(targets):
    commands = parse_list_file(conf.oscmdlist)
    targets_tuple = ()

    for target in targets:
        admin_credentials = None

        if len(target.get_valid_credentials()) == 0:
            continue
        else:
            admin_credentials = get_admin_credentials(target)

        if admin_credentials is False:
            admin_credentials = target.get_valid_credentials()[0]
            logger.warn('No admin user identified for target %s, some commands will not work' % target.get_identity())

        logger.info('Executing OS commands on %s with user %s' % (target.get_identity(), admin_credentials.getUser()))
        smb_shell = SMBShell(target, admin_credentials, conf.name)

        if len(commands) > 0:
            logger.info('Executing OS commands from provided file')

            for command in commands:
                print('OS command \'%s\' output:' % command)

                try:
                    smb_shell.svcexec(command, 'SHARE')
                except SessionError as e:
                    # traceback.print_exc()
                    logger.error('SMB error: %s' % (e.getErrorString(),))
                except NetBIOSTimeout as e:
                    logger.error('SMB connection timed out')
                except keimpxError as e:
                    logger.error(e)
                except KeyboardInterrupt as _:
                    print()
                    logger.info('User aborted')
                    exit()
                except Exception as e:
                    # traceback.print_exc()
                    logger.error(str(e))

                print('----------8<----------')


def smb_cmd_list(targets):
    commands = parse_list_file(conf.smbcmdlist)
    targets_tuple = ()

    for target in targets:
        if len(target.get_valid_credentials()) == 0:
            continue
        else:
            admin_credentials = get_admin_credentials(target)

        if admin_credentials is False:
            admin_credentials = target.get_valid_credentials()[0]
            logger.warn('No admin user identified for target %s, some commands will not work' % target.get_identity())

        logger.info('Executing SMB commands on %s with user %s' % (target.get_identity(), admin_credentials.getUser()))
        shell = InteractiveShell(target, admin_credentials, conf.name)

        if len(commands) > 0:
            logger.info('Executing SMB commands from provided file')

            for command in commands:
                print('SMB command \'%s\' output:' % command)

                try:
                    shell.onecmd(command)
                except SessionError as e:
                    # traceback.print_exc()
                    logger.error('SMB error: %s' % (e.getErrorString(),))
                except NetBIOSTimeout as e:
                    logger.error('SMB connection timed out')
                except keimpxError as e:
                    logger.error(e)
                except KeyboardInterrupt as _:
                    print()
                    logger.info('User aborted')
                    shell.do_exit('')
                except Exception as e:
                    # traceback.print_exc()
                    logger.error(str(e))

                print('----------8<----------')


###############
# Set domains #
###############
def parse_domains_file(filename):
    parsed_domains = []
    try:
        fp = open(filename, 'r')
        file_lines = fp.read().splitlines()
        fp.close()

    except IOError as _:
        logger.error('Could not open domains file %s' % filename)
        return

    file_lines = remove_comments(file_lines)

    for line in file_lines:
        added_domains = add_domain(line)
        for domain in added_domains:
            parsed_domains.append(domain)

    return parsed_domains


def add_domain(line):
    added_domains = []
    _ = str(line).replace(' ', '').split(',')

    for d in _:
        d = d.upper().split('.')[0]
        added_domains.append(d)

    logger.debug('Parsed domain%s: %s' % ('(s)' if len(_) > 1 else '', ', '.join([d for d in _])))
    return added_domains


def set_domains():
    domains = ['']

    logger.info('Loading domains')

    if conf.domain is not None:
        logger.debug('Loading domains from command line')
        added_domains = add_domain(conf.domain)
        for domain in added_domains:
            domains.append(domain)

    if conf.domainsfile is not None:
        logger.debug('Loading domains from file %s' % conf.domainsfile)
        parsed_domains = parse_domains_file(conf.domainsfile)
        for domain in parsed_domains:
            domains.append(domain)

    unique_domains = []
    for domain in domains:
        if domain not in unique_domains:
            unique_domains.append(domain)

    if len(unique_domains) == 0:
        return domains
    elif len(domains) > 0:
        return unique_domains


###################
# Set credentials #
###################
def parse_credentials_file(filename):
    parsed_credentials = []
    try:
        fp = open(filename, 'r')
        file_lines = fp.read().splitlines()
        fp.close()

    except IOError as _:
        logger.error('Could not open credentials file %s' % filename)
        return

    file_lines = remove_comments(file_lines)

    for line in file_lines:
        parsed_credentials.append(add_credentials(line=line))

    if len(parsed_credentials) > 0:
        return parsed_credentials
    else:
        return False


def parse_credentials(credentials_line):
    credentials_line = credentials_line.replace('NO PASSWORD*********************', '00000000000000000000000000000000')

    fgdumpmatch = re.compile(r'^(\S+?):(.*?:?)([0-9a-fA-F]{32}):([0-9a-fA-F]{32}):.*?:.*?:\s*$')
    fgdump = fgdumpmatch.match(credentials_line)

    wcematch = re.compile(r'^(\S+?):.*?:([0-9a-fA-F]{32}):([0-9a-fA-F]{32})\s*$')
    wce = wcematch.match(credentials_line)

    cainmatch = re.compile(r'^(\S+?):.*?:.*?:([0-9a-fA-F]{32}):([0-9a-fA-F]{32})\s*$')
    cain = cainmatch.match(credentials_line)

    plaintextpassmatch = re.compile(r'^(\S+?)\s+(\S*?)$')
    plain = plaintextpassmatch.match(credentials_line)

    # Credentials with hashes (pwdump/pwdumpx/fgdump/pass-the-hash output format)
    if fgdump:
        try:
            binascii.a2b_hex(fgdump.group(3))
            binascii.a2b_hex(fgdump.group(4))

            return fgdump.group(1), '', fgdump.group(3), fgdump.group(4)
        except Exception as _:
            raise credentialsError('credentials error')

    # Credentials with hashes (wce output format)
    elif wce:
        try:
            binascii.a2b_hex(wce.group(2))
            binascii.a2b_hex(wce.group(3))

            return wce.group(1), '', wce.group(2), wce.group(3)
        except Exception as _:
            raise credentialsError('credentials error')

    # Credentials with hashes (cain/l0phtcrack output format)
    elif cain:
        try:
            binascii.a2b_hex(cain.group(2))
            binascii.a2b_hex(cain.group(3))

            return cain.group(1), '', cain.group(2), cain.group(3)
        except Exception as _:
            raise credentialsError('credentials error')

    # Credentials with password (added by user manually divided by a space)
    elif plain:
        return plain.group(1), plain.group(2), '', ''

    else:
        raise credentialsError('credentials error')


def add_credentials(user=None, password='', lmhash='', nthash='', domain='', line=None):
    if line is not None:
        try:
            user, password, lmhash, nthash = parse_credentials(line)

            if user.count('\\') == 1:
                _, user = user.split('\\')
                domain = _
        except credentialsError as _:
            logger.warn('Bad line in credentials file %s: %s' % (conf.credsfile, line))
            return

    if user is not None:
        credential = Credential(user, password, lmhash, nthash, domain)

        logger.debug('Parsed credentials: %s' % credential.get_identity())
        return credential


def set_credentials():
    credentials = []
    logger.info('Loading credentials')

    if conf.user is not None:
        logger.debug('Loading credentials from command line')
        credentials.append(add_credentials(conf.user, conf.password or '', conf.lmhash or '',
                                           conf.nthash or '', conf.domain or ''))

    if conf.credsfile is not None:
        logger.debug('Loading credentials from file %s' % conf.credsfile)
        parsed_credentials = parse_credentials_file(conf.credsfile)
        for credential in parsed_credentials:
            credentials.append(credential)

    unique_credentials = []
    for credential in credentials:
        if credential not in unique_credentials:
            unique_credentials.append(credential)

    if len(unique_credentials) < 1:
        logger.error('No valid credentials loaded')
        sys.exit(1)

    logger.info('Loaded %s unique credential%s' % (len(credentials), 's' if len(credentials) > 1 else ''))
    return unique_credentials


###############
# Set targets #
###############
def parse_targets_file(filename):
    parsed_targets = []

    try:
        fp = open(filename, 'r')
        file_lines = fp.read().splitlines()
        fp.close()

    except IOError as _:
        logger.error('Could not open targets file %s' % filename)
        return

    file_lines = remove_comments(file_lines)

    for line in file_lines:
        parsed_targets.append(add_target(line))

    if len(parsed_targets) > 0:
        return parsed_targets
    else:
        return False


def parse_target(target_line):
    targetmatch = re.compile(r'^([0-9a-zA-Z\-_.]+)(:(\d+))?')
    h = targetmatch.match(str(target_line))

    if h and h.group(3):
        host = h.group(1)
        port = h.group(3)

        if port.isdigit() and 0 < int(port) <= 65535:
            return host, int(port)
        else:
            return host, conf.port

    elif h:
        host = h.group(1)
        return host, conf.port

    else:
        raise targetError('target error')


def add_target(line):
    try:
        host, port = parse_target(line)
    except targetError as _:
        logger.warn('Bad line in targets file %s: %s' % (conf.list, line))
        return
    target = Target(host, port)
    logger.debug('Parsed target: %s' % target.get_identity())
    return target


def addr_to_int(value):
    _ = value.split('.')
    return (int(_[0]) << 24) + (int(_[1]) << 16) + (int(_[2]) << 8) + int(_[3])


def int_to_addr(value):
    return '.'.join(str(value >> n & 0xFF) for n in (24, 16, 8, 0))


def set_targets():
    targets = []
    logger.info('Loading targets')

    if conf.target is not None:
        if '/' not in conf.target:
            logger.debug('Loading targets from command line')
            targets.append(add_target(conf.target))
        else:
            address, mask = re.search(r"([\d.]+)/(\d+)", conf.target).groups()
            logger.debug('Expanding targets from command line')
            start_int = addr_to_int(address) & ~((1 << 32 - int(mask)) - 1)
            end_int = start_int | ((1 << 32 - int(mask)) - 1)
            for _ in range(start_int, end_int):
                targets.append(add_target(int_to_addr(_)))

    if conf.list is not None:
        logger.debug('Loading targets from file %s' % conf.list)
        parsed_targets = parse_targets_file(conf.list)
        if parsed_targets is not False:
            for target in parsed_targets:
                targets.append(target)

    unique_targets = []
    for target in targets:
        if target not in unique_targets:
            unique_targets.append(target)

    if len(unique_targets) < 1:
        logger.error('No valid targets loaded')
        sys.exit(1)

    logger.info('Loaded %s unique target%s' % (len(targets), 's' if len(targets) > 1 else ''))
    return unique_targets


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

    targets = set_targets()
    credentials = set_credentials()
    domains = set_domains()

    for credential in credentials:
        if credential.domain is not None:
            if credential.domain not in domains:
                domains.append(credential.domain)

    if len(domains) == 0:
        logger.info('No domains specified, using a blank domain')
    elif len(domains) > 0:
        logger.info('Loaded %s unique domain%s' % (len(domains), 's' if len(domains) > 1 else ''))

    return targets, credentials, domains


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
            errMsg = 'missing a mandatory parameter (-t or -l), '
            errMsg += '-h for help'
            parser.error(errMsg)

        return args
    except (OptionError, TypeError) as e:
        parser.error(e)

    debugMsg = 'Parsing command line'
    logger.debug(debugMsg)


def banner():
    print('''
    keimpx %s
    by %s
    ''' % (__version__, __author__))


def main():
    global conf
    global have_readline
    global pool_thread

    banner()
    conf = cmdline_parser()
    targets, credentials, domains = check_conf()
    pool_thread = threading.BoundedSemaphore(conf.threads)

    try:
        for target in targets:
            target.update_credentials(credentials)
            target.update_domains(domains)
            pool_thread.acquire()
            current = test_login(target)
            current.daemon = True
            current.start()

        while threading.activeCount() > 1:
            a = 'Caughtit'
            pass

    except KeyboardInterrupt:
        print()
        try:
            logger.warn('Test interrupted')
            a = 'Caughtit'
            stop_threads[0] = True
        except KeyboardInterrupt:
            print()
            logger.info('User aborted')
            exit(1)

    if successes == 0:
        print('\nNo credentials worked on any target\n')
        exit(0)

    print('\nThe credentials worked in total %d times\n' % successes)
    print('TARGET SORTED RESULTS:\n')

    for target in targets:
        valid_credentials = target.get_valid_credentials()

        if len(valid_credentials) > 0:
            print(target.get_identity())

            for valid_credential in valid_credentials:
                print('  %s' % valid_credential.get_identity())

            print()

    print('\nUSER SORTED RESULTS:\n')

    credentials_valid_targets = {}
    for target in targets:
        valid_credentials = target.get_valid_credentials()
        for credential in valid_credentials:
            if credential in credentials_valid_targets:
                credentials_valid_targets[credential].append(target)
            else:
                credentials_valid_targets[credential] = [target]

    for credential, targets in credentials_valid_targets.items():
        print(credential.get_identity(account_details=False))
        for target in targets:
            print('  %s' % target.get_identity())
        print()

    if conf.smbcmdlist is not None:
        smb_cmd_list(targets)

    if conf.oscmdlist is not None:
        os_cmd_list(targets)

    if conf.batch or conf.smbcmdlist or conf.oscmdlist:
        return

    while True:
        msg = 'Do you want to establish a SMB shell from any of the targets? [Y/n] '
        choice = input(msg)

        if choice and choice[0].lower() != 'y':
            return

        counter = 0
        targets_dict = {}
        msg = 'Which target do you want to connect to?'

        for target in targets:
            valid_credentials = target.get_valid_credentials()

            if len(valid_credentials) > 0:
                counter += 1
                msg += '\n[%d] %s%s' % (counter, target.get_identity(), ' (default)' if counter == 1 else '')
                targets_dict[counter] = (target, valid_credentials)

        msg += '\n> '
        choice = read_input(msg, counter)
        user_target, valid_credentials = targets_dict[int(choice)]

        counter = 0
        credentials_dict = {}
        msg = 'Which credentials do you want to use to connect?'

        for credential in valid_credentials:
            counter += 1
            msg += '\n[%d] %s%s' % (counter, credential.get_identity(), ' (default)' if counter == 1 else '')
            credentials_dict[counter] = credential

        msg += '\n> '
        choice = read_input(msg, counter)
        user_credentials = credentials_dict[int(choice)]

        if sys.platform.lower() == 'win32' and have_readline:
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

                debugMsg = 'Leopard libedit detected when using platform\'s '
                debugMsg += 'readline library'
                logger.debug(debugMsg)

                uses_libedit = True

        try:
            shell = InteractiveShell(user_target, user_credentials, conf.name)
            shell.cmdloop()
        except RuntimeError as e:
            logger.error('Runtime error: %s' % str(e))
        except Exception as _:
            # traceback.print_exc()
            pass


if __name__ == '__main__':
    warnings.filterwarnings(action='ignore', category=DeprecationWarning)

    try:
        main()
    except KeyboardInterrupt:
        print()
        logger.info('User aborted')
        exit(1)

    exit(0)
