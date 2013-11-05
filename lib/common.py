#!/usr/bin/env python
# -*- coding: iso-8859-15 -*-
# -*- Mode: python -*-

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
    from impacket.smb3structs import SMB2_DIALECT_002
    from impacket.smb3structs import SMB2_DIALECT_21
    from impacket.smbconnection import SessionError
    from impacket.smbconnection import SMBConnection
    from impacket.smbconnection import SMB_DIALECT
except ImportError:
    sys.stderr.write('You need to install Python Impacket library first.\nGet it from Core Security\'s Google Code repository:\n$ svn checkout http://impacket.googlecode.com/svn/trunk/ impacket\n$ cd impacket\n$ python setup.py build\n$ sudo python setup.py install\n')
    sys.exit(255)

from lib.exceptions import *
from lib.logger import logger

default_share = 'ADMIN$'
default_reg_key = 'HKLM\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\ProductName'
keimpx_path = ''

def check_dialect(dialect):
    if dialect == SMB_DIALECT:
        return 'SMBv1'
    elif dialect == SMB2_DIALECT_002:
        return 'SMBv2.0'
    elif dialect == SMB2_DIALECT_21:
        return 'SMBv2.1'
    else:
        return 'SMBv3.0'

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
