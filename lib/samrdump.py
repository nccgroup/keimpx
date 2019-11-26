#!/usr/bin/env python
# -*- coding: iso-8859-15 -*-
# -*- Mode: python -*-

import sys
from lib.logger import logger

try:
    from impacket.dcerpc.v5 import samr
    from impacket.nt_errors import STATUS_MORE_ENTRIES
    from impacket.dcerpc.v5.rpcrt import DCERPCException
except ImportError:
    sys.stderr.write('Impacket by SecureAuth Corporation is required for this tool to work. Please download it using:'
                     '\npip: pip install -r requirements.txt\nOr through your package manager:\npython-impacket.')
    sys.exit(255)


#################################################################
# Code borrowed and adapted from Impacket's samrdump.py example #
#################################################################
class Samr(object):
    # TODO: port it to DCERPC v5
    # https://code.google.com/p/impacket/source/detail?r=1077&path=/trunk/examples/samrdump.py

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
        self.__samr_domains(False)

        encoding = sys.getdefaultencoding()

        for domain_name, domain in self.domains_dict.items():
            if usrdomain and usrdomain.upper() != domain_name.upper():
                continue

            logger.info('Looking up users in domain %s' % domain_name)

            resp = samr.hSamrLookupDomainInSamServer(self.__dce, self.__mgr_handle, domain)
            resp = samr.hSamrOpenDomain(self.__dce, serverHandle=self.__mgr_handle, domainId=resp['DomainId'])
            self.__domain_context_handle = resp['DomainHandle']
            resp = self.__samr.enumusers(self.__domain_context_handle)

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

            '''
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
            '''

            if self.users_list:
                num = len(self.users_list)
                logger.info('Retrieved %d user%s' % (num, 's' if num > 1 else ''))
            else:
                logger.info('No users enumerated')

            for entry in self.users_list:
                user, uid, info = entry

                print user
                print '  User ID: %d' % uid
                print '  Group ID: %d' % info['PrimaryGroupId']
                if info['UserAccountControl'] & samr.USER_ACCOUNT_DISABLED:
                    account_disabled = 'True'
                else:
                    account_disabled = 'False'
                print '  Enabled: %s' % account_disabled

                try:
                    print '  Logon count: %d' % info['LogonCount']
                except ValueError:
                    pass

                try:
                    print '  Last Logon: %s' % info['LastLogon']
                except ValueError:
                    pass

                try:
                    print '  Last Logoff: %s' % info['LastLogoff']
                except ValueError:
                    pass

                try:
                    print '  Last password set: %s' % info['PasswordLastSet']
                except ValueError:
                    pass

                try:
                    print '  Password expired: %d' % info['PasswordExpired']
                except ValueError:
                    pass

                if info['UserAccountControl'] & samr.USER_DONT_EXPIRE_PASSWORD:
                    dont_expire = 'True'
                else:
                    dont_expire = 'False'

                try:
                    print '  Password does not expire: %d' % dont_expire
                except ValueError:
                    pass

                try:
                    print '  Password can change: %s' % info['PasswordCanChange']
                except ValueError:
                    pass

                try:
                    print '  Password must change: %s' % info['PasswordMustChange']
                except ValueError:
                    pass

                try:
                    print '  Bad password count: %d' % info['BadPasswordCount']
                except ValueError:
                    pass

                try:
                    print '  Full name: %d' % info['FullName']
                except ValueError:
                    pass

                try:
                    print '  Home directory: %d' % info['HomeDirectory']
                except ValueError:
                    pass

                try:
                    print '  Home directory drive: %d' % info['HomeDirectoryDrive']
                except ValueError:
                    pass

                try:
                    print '  Script path: %d' % info['ScriptPath']
                except ValueError:
                    pass

                try:
                    print '  Profile path: %d' % info['ProfilePath']
                except ValueError:
                    pass

                try:
                    print '  Admin comment: %d' % info['AdminComment']
                except ValueError:
                    pass

                try:
                    print '  Workstations: %d' % info['WorkStations']
                except ValueError:
                    pass

                try:
                    print '  User comment: %d' % info['UserComment']
                except ValueError:
                    pass

            self.users_list = set()

    def __samr_pswpolicy(self, usrdomain=None):
        """
        Enumerate password policy on the system
        """
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
        """
        Enumerate domains to which the system is part of
        """
        logger.info('Enumerating domains')

        resp = samr.hSamrEnumerateDomainsInSamServer(self.__dce, self.__mgr_handle)
        domains = resp['Buffer']['Buffer']

        if display is True:
            print 'Domains:'

        for domain in domains:
            domain_name = domain['Name']

            if domain_name not in self.domains_dict:
                self.domains_dict[domain_name] = domain

            if display is True:
                print '  %s' % domain_name
