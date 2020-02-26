#!/usr/bin/env python
# -*- coding: iso-8859-15 -*-
# -*- Mode: python -*-

from __future__ import division
from __future__ import print_function

import sys

from lib.logger import logger

try:
    from impacket import uuid, version
    from impacket.dcerpc.v5 import transport, epm
except ImportError:
    sys.stderr.write("rpcdump: Impacket import error")
    sys.stderr.write("Impacket by SecureAuth Corporation is required for this tool to work. Please download it using:"
                     "\npip: pip install -r requirements.txt\nOr through your package manager:\npython-impacket.")
    sys.exit(255)


################################################################
# Code borrowed and adapted from Impacket's rpcdump.py example #
################################################################


class RPCDump:
    KNOWN_PROTOCOLS = {
        135: {"bindstr": r"ncacn_ip_tcp:%s", "set_host": False},
        139: {"bindstr": r"ncacn_np:%s[\pipe\epmapper]", "set_host": True},
        445: {"bindstr": r"ncacn_np:%s[\pipe\epmapper]", "set_host": True}
    }

    def __init__(self, remoteName, remoteHost="", username="", password="", domain="", lmhash="", nthash="", port=135):

        self.__remoteName = remoteName if remoteName is not None else remoteHost
        self.__remoteHost = remoteHost if remoteHost is not None else remoteName
        self.__username = username
        self.__password = password
        self.__domain = domain
        self.__lmhash = lmhash
        self.__nthash = nthash
        self.__port = port

    def dump(self):
        """Dumps the list of endpoints registered with the mapper
        listening at addr. self.__remoteName is a valid host name or IP
        address in string format.
        """

        logger.info("Retrieving endpoint list from %s" % self.__remoteName)

        entries = []

        stringbinding = self.KNOWN_PROTOCOLS[self.__port]["bindstr"] % self.__remoteName
        logger.debug("StringBinding %s" % stringbinding)
        rpctransport = transport.DCERPCTransportFactory(stringbinding)
        rpctransport.set_dport(self.__port)

        if self.KNOWN_PROTOCOLS[self.__port]["set_host"]:
            rpctransport.setRemoteHost(self.__remoteHost)

        if hasattr(rpctransport, "set_credentials"):
            # This method exists only for selected protocol sequences.
            rpctransport.set_credentials(self.__username, self.__password, self.__domain,
                                         self.__lmhash, self.__nthash)

        try:
            entries = self.__fetchList(rpctransport)
        except Exception as e:
            logger.critical("Protocol failed: %s" % e)

        # Display results.

        endpoints = {}
        # Let's group the UUIDS
        for entry in entries:
            binding = epm.PrintStringBinding(entry["tower"]["Floors"], rpctransport.getRemoteHost())
            tmpUUID = str(entry["tower"]["Floors"][0])
            if (tmpUUID in endpoints) is not True:
                endpoints[tmpUUID] = {}
                endpoints[tmpUUID]["Bindings"] = list()
            if uuid.uuidtup_to_bin(uuid.string_to_uuidtup(tmpUUID))[:18] in epm.KNOWN_UUIDS:
                endpoints[tmpUUID]["EXE"] = epm.KNOWN_UUIDS[uuid.uuidtup_to_bin(uuid.string_to_uuidtup(tmpUUID))[:18]]
            else:
                endpoints[tmpUUID]["EXE"] = "N/A"
            endpoints[tmpUUID]["annotation"] = entry["annotation"][:-1].decode("utf-8")
            endpoints[tmpUUID]["Bindings"].append(binding)

            if tmpUUID[:36] in epm.KNOWN_PROTOCOLS:
                endpoints[tmpUUID]["Protocol"] = epm.KNOWN_PROTOCOLS[tmpUUID[:36]]
            else:
                endpoints[tmpUUID]["Protocol"] = "N/A"
            # print "Transfer Syntax: %s" % entry["Tower"]["Floors"][1]

        for endpoint in list(endpoints.keys()):
            print("Protocol: %s " % endpoints[endpoint]["Protocol"])
            print("Provider: %s " % endpoints[endpoint]["EXE"])
            print("UUID    : %s %s" % (endpoint, endpoints[endpoint]["annotation"]))
            print("Bindings: ")
            for binding in endpoints[endpoint]["Bindings"]:
                print("          %s" % binding)
            print("")

        if entries:
            num = len(entries)
            if 1 == num:
                logger.info("Received one endpoint.")
            else:
                logger.info("Received %d endpoints." % num)
        else:
            logger.info("No endpoints found.")

    def __fetchList(self, rpctransport):
        dce = rpctransport.get_dce_rpc()

        dce.connect()
        # dce.set_auth_level(ntlm.NTLM_AUTH_PKT_INTEGRITY)
        # dce.bind(epm.MSRPC_UUID_PORTMAP)
        # rpcepm = epm.DCERPCEpm(dce)

        resp = epm.hept_lookup(None, dce=dce)

        dce.disconnect()

        return resp
