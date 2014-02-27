#!/usr/bin/env python
# -*- coding: iso-8859-15 -*-
# -*- Mode: python -*-

from lib.common import *
from lib.polenum import *

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
        self.__dce.bind(MSRPC_UUID_SAMR)
        self.__samr = DCERPCSamr(self.__dce)
        self.__resp = self.__samr.connect()
        self.__mgr_handle = self.__resp.get_context_handle()

    def __samr_disconnect(self):
        '''
        Disconnect from samr named pipe
        '''
        logger.debug('Disconnecting from the SAMR named pipe')

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
