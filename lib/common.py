#!/usr/bin/env python
# -*- coding: iso-8859-15 -*-
# -*- Mode: python -*-

import logging
import os
import sys
import tempfile
from threading import Thread

from six import string_types
from six import integer_types
from six.moves import input as input
from six.moves.configparser import ConfigParser

from lib.logger import logger

try:
    from impacket import smbserver
    from impacket.smb3structs import SMB2_DIALECT_002
    from impacket.smb3structs import SMB2_DIALECT_21
    from impacket.smbconnection import SMB_DIALECT
except ImportError:
    sys.stderr.write('common: Impacket import error')
    sys.stderr.write('common: Impacket by SecureAuth Corporation is required for this tool to work. Please download it'
                     ' using:\npip: pip install -r requirements.txt\nOr through your package manager:'
                     '\npython-impacket.')
    sys.exit(255)

keimpx_path = ''


class DataStore(object):
    cmd_stdout = ''
    default_reg_key = r'HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProductName'
    server_os = None
    server_name = None
    server_domain = None
    share_path = None
    user_path = 'C:\\'
    version_major = None
    version_minor = None
    writable_share = 'ADMIN$'


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
        choice = input(msg)

        if choice == '':
            choice = 1
            break
        elif choice.isdigit() and 1 <= int(choice) <= counter:
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


def set_verbosity(level="0"):
    if isinstance(level, string_types) and level.isdigit():
        level = int(level)

    if level == 0:
        logger.setLevel(logging.WARNING)
    elif level == 1:
        logger.setLevel(logging.INFO)
    elif level > 1:
        logger.setLevel(logging.DEBUG)


class RemoteFile:
    def __init__(self, smb_connection, filename, share='ADMIN$'):
        self.smb = smb_connection
        self.__filename = filename
        self.__share = share
        self.__tid = self.smb.connectTree(self.__share)
        self.__fid = None
        self.__currentOffset = 0

    def open(self):
        self.__fid = self.smb.openFile(self.__tid, self.__filename)

    def seek(self, offset, whence):
        # Implement whence, for now it is always from the beginning of the file
        if whence == 0:
            self.__currentOffset = offset

    def read(self, bytesToRead):
        if bytesToRead > 0:
            data = self.smb.readFile(self.__tid, self.__fid, self.__currentOffset, bytesToRead)
            self.__currentOffset += len(data)

            return data

        return ''

    def close(self):
        if self.__fid is not None:
            self.smb.closeFile(self.__tid, self.__fid)
            self.smb.deleteFile(self.__share, self.__filename)
            self.__fid = None

    def tell(self):
        return self.__currentOffset

    def __str__(self):
        return '%s\\%s' % (self.__share, self.__filename)


def is_local_admin():
    """
    Returns True if the current process is run under admin privileges
    """

    isAdmin = None

    if os.name in ('posix', 'mac'):
        _ = os.geteuid()

        isAdmin = isinstance(_, (integer_types, float)) and _ == 0
    elif sys.platform.lower() == 'win32':
        import ctypes

        _ = ctypes.windll.shell32.IsUserAnAdmin()

        isAdmin = isinstance(_, (integer_types, float)) and _ == 1
    else:
        errMsg = "keimpx is not able to check if you are running it "
        errMsg += "as an administrator account on this platform. "
        errMsg += "keimpx will assume that you are an administrator "
        errMsg += "which is mandatory for the requested attack "
        errMsg += "to work properly"
        logger.error(errMsg)

        isAdmin = True

    return isAdmin
