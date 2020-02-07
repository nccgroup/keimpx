#!/usr/bin/env python
# -*- coding: iso-8859-15 -*-
# -*- Mode: python -*-
import sys
from datetime import datetime
from time import strftime, gmtime

from six.moves import range as range

from lib.logger import logger

try:
    from impacket.dcerpc.v5 import samr
    from impacket.nt_errors import STATUS_MORE_ENTRIES
    from impacket.dcerpc.v5.rpcrt import DCERPCException
except ImportError:
    sys.stderr.write('samrdump: Impacket import error')
    sys.stderr.write('Impacket by SecureAuth Corporation is required for this tool to work. Please download it using:'
                     '\npip: pip install -r requirements.txt\nOr through your package manager:\npython-impacket.')
    sys.exit(255)


#################################################################
# Code borrowed and adapted from Impacket's samrdump.py example #
#################################################################
class Samr(object):

    def __init__(self):
        pass

    @staticmethod
    def getUnixTime(t):
        t -= 116444736000000000
        t /= 10000000
        return t

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
        self.__dce.bind(samr.MSRPC_UUID_SAMR)
        self.__resp = samr.hSamrConnect(self.__dce)
        self.__mgr_handle = self.__resp['ServerHandle']

    def __samr_disconnect(self):
        '''
        Disconnect from samr named pipe
        '''
        logger.debug('Disconnecting from the SAMR named pipe')

        self.__dce.disconnect()

    def __samr_users(self, usrdomain=None):
        '''
        Enumerate users on the system
        '''
        self.__samr_domains(True)

        encoding = sys.getdefaultencoding()

        for domain_name, domain in self.domains_dict.items():
            if usrdomain and usrdomain.upper() != domain_name.upper():
                continue

            logger.info('Looking up users in domain %s' % domain_name)

            resp = samr.hSamrLookupDomainInSamServer(self.__dce, self.__mgr_handle, domain_name)
            resp = samr.hSamrOpenDomain(self.__dce, serverHandle=self.__mgr_handle, domainId=resp['DomainId'])
            self.__domain_context_handle = resp['DomainHandle']

            status = STATUS_MORE_ENTRIES
            enum_context = 0
            while status == STATUS_MORE_ENTRIES:
                try:
                    resp = samr.hSamrEnumerateUsersInDomain(self.__dce, self.__domain_context_handle,
                                                            enumerationContext=enum_context)
                except DCERPCException as e:
                    if str(e).find('STATUS_MORE_ENTRIES') < 0:
                        raise
                    resp = e.get_packet()

                for user in resp['Buffer']['Buffer']:
                    r = samr.hSamrOpenUser(self.__dce, self.__domain_context_handle,
                                           samr.MAXIMUM_ALLOWED, user['RelativeId'])
                    logger.debug('Found user %s (UID: %d)' % (user['Name'], user['RelativeId']))
                    info = samr.hSamrQueryInformationUser2(self.__dce, r['UserHandle'],
                                                           samr.USER_INFORMATION_CLASS.UserAllInformation)
                    entry = (user['Name'], user['RelativeId'], info['Buffer']['All'])
                    self.users_list.add(entry)
                    samr.hSamrCloseHandle(self.__dce, r['UserHandle'])

                enum_context = resp['EnumerationContext']
                status = resp['ErrorCode']

            if self.users_list:
                num = len(self.users_list)
                logger.info('Retrieved %d user%s' % (num, 's' if num > 1 else ''))
            else:
                logger.info('No users enumerated')

            for entry in self.users_list:
                user, uid, info = entry

                print(user)
                print('  User ID: %d' % uid)
                print('  Group ID: %d' % info['PrimaryGroupId'])
                if info['UserAccountControl'] & samr.USER_ACCOUNT_DISABLED:
                    account_disabled = 'True'
                else:
                    account_disabled = 'False'
                print('  Enabled: %s' % account_disabled)

                try:
                    print('  Logon count: %d' % info['LogonCount'])
                except ValueError:
                    pass

                lastLogon = (info['LastLogon']['HighPart'] << 32) + info['LastLogon']['LowPart']
                if lastLogon == 0:
                    lastLogon = '<never>'
                else:
                    lastLogon = str(datetime.fromtimestamp(self.getUnixTime(lastLogon)))

                try:
                    print('  Last Logon: %s' % lastLogon)
                except ValueError:
                    pass

                lastLogoff = (info['LastLogoff']['HighPart'] << 32) + info['LastLogoff']['LowPart']
                if lastLogoff == 0:
                    lastLogoff = '<never>'
                else:
                    lastLogoff = str(datetime.fromtimestamp(self.getUnixTime(lastLogoff)))

                try:
                    print('  Last Logoff: %s' % lastLogoff)
                except ValueError:
                    pass

                pwdLastSet = (info['PasswordLastSet']['HighPart'] << 32) + info['PasswordLastSet']['LowPart']
                if pwdLastSet == 0:
                    pwdLastSet = '<never>'
                else:
                    pwdLastSet = str(datetime.fromtimestamp(self.getUnixTime(pwdLastSet)))

                try:
                    print('  Last password set: %s' % pwdLastSet)
                except ValueError:
                    pass

                if info['PasswordExpired'] == 0:
                    password_expired = 'False'
                elif info['PasswordExpired'] == 1:
                    password_expired = 'True'

                try:
                    print('  Password expired: %s' % password_expired)
                except ValueError:
                    pass

                if info['UserAccountControl'] & samr.USER_DONT_EXPIRE_PASSWORD:
                    dont_expire = 'True'
                else:
                    dont_expire = 'False'

                try:
                    print('  Password does not expire: %s' % dont_expire)
                except ValueError:
                    pass

                pwdCanChange = (info['PasswordCanChange']['HighPart'] << 32) + info['PasswordCanChange']['LowPart']
                if pwdCanChange == 0:
                    pwdCanChange = '<never>'
                else:
                    pwdCanChange = str(datetime.fromtimestamp(self.getUnixTime(pwdCanChange)))

                try:
                    print('  Password can change: %s' % pwdCanChange)
                except ValueError:
                    pass

                try:
                    pwdMustChange = (info['PasswordMustChange']['HighPart'] << 32) + info['PasswordMustChange'][
                        'LowPart']
                    if pwdMustChange == 0:
                        pwdMustChange = '<never>'
                    else:
                        pwdMustChange = str(datetime.fromtimestamp(self.getUnixTime(pwdMustChange)))
                except:
                    pwdMustChange = '<never>'

                try:
                    print('  Password must change: %s' % pwdMustChange)
                except ValueError:
                    pass

                try:
                    print('  Bad password count: %d' % info['BadPasswordCount'])
                except ValueError:
                    pass

                try:
                    print('  Full name: %s' % info['FullName'])
                except ValueError:
                    pass

                try:
                    print('  Home directory: %s' % info['HomeDirectory'])
                except ValueError:
                    pass

                try:
                    print('  Home directory drive: %s' % info['HomeDirectoryDrive'])
                except ValueError:
                    pass

                try:
                    print('  Script path: %s' % info['ScriptPath'])
                except ValueError:
                    pass

                try:
                    print('  Profile path: %s' % info['ProfilePath'])
                except ValueError:
                    pass

                try:
                    print('  Admin comment: %s' % info['AdminComment'])
                except ValueError:
                    pass

                try:
                    print('  Workstations: %s' % info['WorkStations'])
                except ValueError:
                    pass

                try:
                    print('  User comment: %s' % info['UserComment'])
                except ValueError:
                    pass

            self.users_list = set()

    def __samr_pswpolicy(self, usrdomain=None):
        self.__samr_domains(False)

        for domain_name, domain in self.domains_dict.items():
            if usrdomain and usrdomain.upper() != domain_name.upper():
                continue

            print('Looking up password policy in domain %s' % domain_name)

            resp = samr.hSamrLookupDomainInSamServer(self.__dce, serverHandle=self.__mgr_handle, name=domain_name)
            if resp['ErrorCode'] != 0:
                raise Exception('Connect error')

            resp = samr.hSamrOpenDomain(self.__dce, serverHandle=self.__mgr_handle, desiredAccess=samr.MAXIMUM_ALLOWED,
                                        domainId=resp['DomainId'])
            if resp['ErrorCode'] != 0:
                raise Exception('Connect error')
            domainHandle = resp['DomainHandle']
            # End Setup

            domain_passwd = samr.DOMAIN_INFORMATION_CLASS.DomainPasswordInformation
            re = samr.hSamrQueryInformationDomain2(
                self.__dce, domainHandle=domainHandle,
                domainInformationClass=domain_passwd)
            self.__min_pass_len = (re['Buffer']['Password']['MinPasswordLength'] or "None")
            pass_hist_len = re['Buffer']['Password']['PasswordHistoryLength']
            self.__pass_hist_len = pass_hist_len or "None"
            self.__max_pass_age = convert(
                int(re['Buffer']['Password']['MaxPasswordAge']['LowPart']),
                int(re['Buffer']['Password']['MaxPasswordAge']['HighPart']))
            self.__min_pass_age = convert(
                int(re['Buffer']['Password']['MinPasswordAge']['LowPart']),
                int(re['Buffer']['Password']['MinPasswordAge']['HighPart']))
            self.__pass_prop = d2b(re['Buffer']['Password']['PasswordProperties'])

            domain_lockout = samr.DOMAIN_INFORMATION_CLASS.DomainLockoutInformation
            re = samr.hSamrQueryInformationDomain2(
                self.__dce, domainHandle=domainHandle,
                domainInformationClass=domain_lockout)
            self.__rst_accnt_lock_counter = convert(
                0,
                re['Buffer']['Lockout']['LockoutObservationWindow'],
                lockout=True)
            self.__lock_accnt_dur = convert(
                0,
                re['Buffer']['Lockout']['LockoutDuration'],
                lockout=True)
            self.__accnt_lock_thres = re['Buffer']['Lockout']['LockoutThreshold'] or "None"

            domain_logoff = samr.DOMAIN_INFORMATION_CLASS.DomainLogoffInformation
            re = samr.hSamrQueryInformationDomain2(
                self.__dce, domainHandle=domainHandle,
                domainInformationClass=domain_logoff)
            self.__force_logoff_time = convert(
                re['Buffer']['Logoff']['ForceLogoff']['LowPart'],
                re['Buffer']['Logoff']['ForceLogoff']['HighPart'])

            self.print_friendly()

    def print_friendly(self):
        PASSCOMPLEX = {
            5: 'Domain Password Complex:',
            4: 'Domain Password No Anon Change:',
            3: 'Domain Password No Clear Change:',
            2: 'Domain Password Lockout Admins:',
            1: 'Domain Password Store Cleartext:',
            0: 'Domain Refuse Password Change:'
        }

        print("\n[+] Minimum password length: {0}".format(
            self.__min_pass_len))
        print("[+] Password history length: {0}".format(
            self.__pass_hist_len))
        print("[+] Maximum password age: {0}".format(self.__max_pass_age))
        print("[+] Password Complexity Flags: {0}\n".format(
            self.__pass_prop or "None"))

        for i, a in enumerate(self.__pass_prop):
            print("[+] {0} {1}".format(PASSCOMPLEX[i], str(a)))

        print("\n[+] Minimum password age: {0}".format(self.__min_pass_age))
        print("[+] Reset Account Lockout Counter: {0}".format(
            self.__rst_accnt_lock_counter))
        print("[+] Locked Account Duration: {0}".format(
            self.__lock_accnt_dur))
        print("[+] Account Lockout Threshold: {0}".format(
            self.__accnt_lock_thres))
        print("[+] Forced Log off Time: {0}".format(
            self.__force_logoff_time))
        return

    def __samr_domains(self, display=True):
        """
        Enumerate domains to which the system is part of
        """
        logger.info('Enumerating domains')

        resp = samr.hSamrEnumerateDomainsInSamServer(self.__dce, self.__mgr_handle)
        domains = resp['Buffer']['Buffer']

        if display is True:
            print('Domains:')

        for domain in domains:
            domain_name = domain['Name']

            if domain_name not in self.domains_dict:
                self.domains_dict[domain_name] = domain

            if display is True:
                print('  %s' % domain_name)


def d2b(a):
    tbin = []
    while a:
        tbin.append(a % 2)
        a //= 2

    t2bin = tbin[::-1]
    if len(t2bin) != 8:
        for x in range(6 - len(t2bin)):
            t2bin.insert(0, 0)
    return ''.join([str(g) for g in t2bin])


def convert(low, high, lockout=False):
    time = ""
    tmp = 0

    if low == 0 and hex(high) == "-0x80000000":
        return "Not Set"
    if low == 0 and high == 0:
        return "None"

    if not lockout:
        if (low != 0):
            high = abs(high + 1)
        else:
            high = abs(high)
            low = abs(low)

        tmp = low + (high) * 16 ** 8  # convert to 64bit int
        tmp *= (1e-7)  # convert to seconds
    else:
        tmp = abs(high) * (1e-7)

    try:
        minutes = int(strftime("%M", gmtime(tmp)))
        hours = int(strftime("%H", gmtime(tmp)))
        days = int(strftime("%j", gmtime(tmp))) - 1
    except ValueError as e:
        return "[-] Invalid TIME"

    if days > 1:
        time += "{0} days ".format(days)
    elif days == 1:
        time += "{0} day ".format(days)
    if hours > 1:
        time += "{0} hours ".format(hours)
    elif hours == 1:
        time += "{0} hour ".format(hours)
    if minutes > 1:
        time += "{0} minutes ".format(minutes)
    elif minutes == 1:
        time += "{0} minute ".format(minutes)
    return time
