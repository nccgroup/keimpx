#!/usr/bin/env python
# -*- coding: iso-8859-15 -*-
# -*- Mode: python -*-

from lib.common import *

################################################################
# Code borrowed and adapted from Impacket's rpcdump.py example #
################################################################
class RpcDump(object):
    def __init__(self):
        pass

    def rpcdump(self):
        logger.info('Retrieving RPC endpoint list')

        self.__rpc_connect()
        entries = self.__fetchList()
        endpoints = {}

        # Let's groups the UUIDS
        for entry in entries:
            binding = epm.PrintStringBinding(entry['tower']['Floors'], self.trans.get_dip())
            tmpUUID = str(entry['tower']['Floors'][0])

            if endpoints.has_key(tmpUUID) is not True:
                endpoints[tmpUUID] = {}
                endpoints[tmpUUID]['Bindings'] = list()

            if ndrutils.KNOWN_UUIDS.has_key(uuid.uuidtup_to_bin(uuid.string_to_uuidtup(tmpUUID))[:18]):
                endpoints[tmpUUID]['EXE'] = ndrutils.KNOWN_UUIDS[uuid.uuidtup_to_bin(uuid.string_to_uuidtup(tmpUUID))[:18]]
            else:
                endpoints[tmpUUID]['EXE'] = 'N/A'

            endpoints[tmpUUID]['annotation'] = entry['annotation'][:-1]
            endpoints[tmpUUID]['Bindings'].append(binding)

            if epm.KNOWN_PROTOCOLS.has_key(tmpUUID[:36]):
                endpoints[tmpUUID]['Protocol'] = epm.KNOWN_PROTOCOLS[tmpUUID[:36]]
            else:
                endpoints[tmpUUID]['Protocol'] = 'N/A'

            #print 'Transfer Syntax: %s' % entry['Tower']['Floors'][1]
     
        for endpoint in endpoints.keys():
            print 'Protocol: %s ' % endpoints[endpoint]['Protocol']
            print 'Provider: %s ' % endpoints[endpoint]['EXE']
            print 'UUID    : %s %s' % (endpoint, endpoints[endpoint]['annotation'])
            print 'Bindings: '

            for binding in endpoints[endpoint]['Bindings']:
                print '          %s' % binding

            print

        if entries:
            num = len(entries)

            if 1 == num:
                logger.info('Received one RPC endpoint')
            else:
                logger.info('Received %d endpoints' % num)
        else:
            logger.info('No endpoints found')

    def __rpc_connect(self):
        '''
        Connect to epmapper named pipe
        '''
        logger.debug('Connecting to the epmapper named pipe')
        self.smb_transport('epmapper')

        self.__dce = self.trans.get_dce_rpc()
        self.__dce.connect()
        #self.__dce.set_auth_level(ntlm.NTLM_AUTH_PKT_PRIVACY)
        #self.__dce.bind(epm.MSRPC_UUID_PORTMAP)

    def __rpc_disconnect(self):
        '''
        Disconnect from epmapper named pipe
        '''
        logger.debug('Disconnecting from the epmapper named pipe')
        self.__dce.disconnect()

    def __fetchList(self):
        entries = []
        resp = epm.hept_lookup(self.trans.get_dip())
        self.__rpc_disconnect()

        return resp
