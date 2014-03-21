#!/usr/bin/env python
# -*- coding: iso-8859-15 -*-
# -*- Mode: python -*-

from lib.common import *
from lib.smbexec import SvcShell

#################################################################
# Code borrowed and adapted from Impacket's services.py example #
#################################################################
class SvcCtl(object):
    def __init__(self):
        pass

    def services(self, srvname):
        self.__scmr_connect()
        self.__scmr_list(srvname)
        self.__scmr_disconnect()

    def status(self, srvname, return_state=False):
        self.__scmr_connect()
        self.__scmr_srv_manager(srvname)
        resp = self.__scmr_state(srvname, return_state)
        self.__scmr_disconnect()

        return resp

    def query(self, srvname, return_answer=False):
        self.__scmr_connect()
        self.__scmr_srv_manager(srvname)
        resp = self.__scmr_config(srvname, return_answer)
        self.__scmr_disconnect()

        return resp

    def start(self, srvname, srvargs=''):
        self.__scmr_connect()
        self.__scmr_srv_manager(srvname)
        self.__scmr_start(srvname, srvargs)
        self.__scmr_disconnect(srvname)

    def stop(self, srvname):
        self.__scmr_connect()
        self.__scmr_srv_manager(srvname)
        self.__scmr_stop(srvname)
        self.__scmr_disconnect(srvname)

    def change(self, srvname, display=None, path=None, service_type=None, start_type=None, start_name=None, password=None):
        self.__scmr_connect()
        self.__scmr_srv_manager(srvname)
        self.__scmr_change(display, path, service_type, start_type, start_name, password)
        self.__scmr_disconnect(srvname)

    def deploy(self, srvname, local_file=None, srvargs='', remote_file=None, displayname=None):
        self.oldpwd = self.pwd
        self.pwd = '\\'

        self.__scmr_bin_upload(local_file, remote_file)
        self.__scmr_connect()
        self.__scmr_create(srvname, remote_file, displayname)
        self.__scmr_srv_manager(srvname)
        self.__scmr_start(srvname, srvargs)
        self.__scmr_disconnect(srvname)

        self.pwd = self.oldpwd

    def undeploy(self, srvname):
        self.oldpwd = self.pwd
        self.pwd = '\\'

        self.__scmr_connect()
        self.__scmr_srv_manager(srvname)
        resp = scmr.hRQueryServiceConfigW(self.__rpc, self.__service_handle)
        remote_file = resp['lpServiceConfig']['lpBinaryPathName'][:-1]
        remote_file = str(os.path.basename(remote_file.replace('\\', '/')))

        if self.__scmr_state(srvname, return_state=True) == 'RUNNING':
            self.__scmr_stop(srvname)

        self.__scmr_delete(srvname)
        self.__scmr_disconnect(srvname)
        self.__scmr_bin_remove(remote_file)
        self.pwd = self.oldpwd

    def svcexec(self, command, mode='SHARE', display=True):
        if mode == 'SERVER' and not is_local_admin():
            err = "you need to run keimpx as an administrator. keimpx "
            err += "needs to listen on TCP port a SMB server for "
            err += "incoming connection attempts"
            raise missingPermission(err)

        command_and_args = shlex.split(command)

        if os.path.exists(command_and_args[0]):
            self.use(DataStore.writable_share)
            self.upload(command_and_args[0])

        self.__scmr_connect()

        try:
            if mode == 'SERVER':
                self.__serverThread = SMBServer(self.smbserver_share)
                self.__serverThread.daemon = True
                self.__serverThread.start()

            if os.path.exists(command_and_args[0]):
                command = ntpath.join(DataStore.share_path, os.path.basename(command))

            self.svc_shell = SvcShell(self.__rpc, self.__mgr_handle, self.trans, self.smbserver_share, mode, display)
            self.svc_shell.onecmd(command)

            if mode == 'SERVER':
                self.__serverThread.stop()
        except SessionError, e:
            #traceback.print_exc()
            logger.error('SMB error: %s' % (e.getErrorString(), ))
        except KeyboardInterrupt, _:
            print
            logger.info('User aborted')
        except Exception, e:
            #traceback.print_exc()
            logger.error(str(e))

        sys.stdout.flush()
        self.__scmr_disconnect()

        if os.path.exists(command_and_args[0]):
            self.rm(os.path.basename(command_and_args[0]))

    def svcshell(self, mode='SHARE'):
        if mode == 'SERVER' and not is_local_admin():
            err = "you need to run keimpx as an administrator. keimpx "
            err += "needs to listen on TCP port a SMB server for "
            err += "incoming connection attempts"
            raise missingPermission(err)

        self.__scmr_connect()

        try:
            if mode == 'SERVER':
                self.__serverThread = SMBServer(self.smbserver_share)
                self.__serverThread.daemon = True
                self.__serverThread.start()

            self.svc_shell = SvcShell(self.__rpc, self.__mgr_handle, self.trans, self.smbserver_share, mode)
            self.svc_shell.cmdloop()

            if mode == 'SERVER':
                self.__serverThread.stop()
        except SessionError, e:
            #traceback.print_exc()
            logger.error('SMB error: %s' % (e.getErrorString(), ))
        except KeyboardInterrupt, _:
            print
            logger.info('User aborted')
        except Exception, e:
            #traceback.print_exc()
            logger.error(str(e))

        sys.stdout.flush()
        self.__scmr_disconnect()

    def __scmr_srv_manager(self, srvname):
        self.__resp = scmr.hROpenServiceW(self.__rpc, self.__mgr_handle, '%s\x00' % srvname)
        self.__service_handle = self.__resp['lpServiceHandle']

    def __scmr_connect(self):
        '''
        Connect to svcctl named pipe
        '''
        self.smb_transport('svcctl')

        self.__dce = self.trans.get_dce_rpc()
        self.__dce.bind(scmr.MSRPC_UUID_SCMR)
        self.__rpc = self.__dce
        self.__resp = scmr.hROpenSCManagerW(self.__dce)
        self.__mgr_handle = self.__resp['lpScHandle']

    def __scmr_disconnect(self, srvname=None):
        '''
        Disconnect from svcctl named pipe
        '''
        if srvname:
            scmr.hRCloseServiceHandle(self.__rpc, self.__service_handle)

        if self.__mgr_handle:
            scmr.hRCloseServiceHandle(self.__rpc, self.__mgr_handle)

        self.__dce.disconnect()

    def __scmr_bin_upload(self, local_file, remote_file):
        '''
        Upload the service executable
        '''
        self.use(DataStore.writable_share)
        self.__pathname = ntpath.join(DataStore.writable_share, remote_file)
        logger.info('Uploading the service executable to %s' % self.__pathname)
        self.upload(local_file, remote_file)

    def __scmr_bin_remove(self, remote_file):
        '''
        Remove the service executable
        '''
        self.use(DataStore.writable_share)
        self.__pathname = ntpath.join(DataStore.writable_share, remote_file)
        logger.info('Removing the service executable %s' % self.__pathname)
        self.rm(remote_file)

    def __scmr_create(self, srvname, remote_file, displayname=None):
        '''
        Create the service
        '''
        logger.info('Creating the service %s' % srvname)

        if not displayname:
            displayname = srvname

        self.__pathname = ntpath.join(DataStore.share_path, remote_file)
        scmr.hRCreateServiceW(self.__rpc, self.__mgr_handle, '%s\x00' % srvname, '%s\x00' % displayname, lpBinaryPathName='%s\x00' % self.__pathname)

    def __scmr_delete(self, srvname):
        '''
        Delete the service
        '''
        logger.info('Deleting the service %s' % srvname)
        scmr.hRDeleteService(self.__rpc, self.__service_handle)

    def __scmr_parse_config(self, resp):
        print 'TYPE              : %2d - ' % resp['lpServiceConfig']['dwServiceType'],

        if resp['lpServiceConfig']['dwServiceType'] & 0x1:
            print 'SERVICE_KERNLE_DRIVER'
        if resp['lpServiceConfig']['dwServiceType'] & 0x2:
            print 'SERVICE_FILE_SYSTEM_DRIVER'
        if resp['lpServiceConfig']['dwServiceType'] & 0x10:
            print 'SERVICE_WIN32_OWN_PROCESS'
        if resp['lpServiceConfig']['dwServiceType'] & 0x20:
            print 'SERVICE_WIN32_SHARE_PROCESS'
        if resp['lpServiceConfig']['dwServiceType'] & 0x100:
            print 'SERVICE_INTERACTIVE_PROCESS'

        print 'START_TYPE        : %2d - ' % resp['lpServiceConfig']['dwStartType'],

        if resp['lpServiceConfig']['dwStartType'] == 0x0:
            print 'BOOT START'
        elif resp['lpServiceConfig']['dwStartType'] == 0x1:
            print 'SYSTEM START'
        elif resp['lpServiceConfig']['dwStartType'] == 0x2:
            print 'AUTO START'
        elif resp['lpServiceConfig']['dwStartType'] == 0x3:
            print 'DEMAND START'
        elif resp['lpServiceConfig']['dwStartType'] == 0x4:
            print 'DISABLED'
        else:
            print 'UNKOWN'

        print 'ERROR_CONTROL     : %2d - ' % resp['lpServiceConfig']['dwErrorControl'],

        if resp['lpServiceConfig']['dwErrorControl'] == 0x0:
            print 'IGNORE'
        elif resp['lpServiceConfig']['dwErrorControl'] == 0x1:
            print 'NORMAL'
        elif resp['lpServiceConfig']['dwErrorControl'] == 0x2:
            print 'SEVERE'
        elif resp['lpServiceConfig']['dwErrorControl'] == 0x3:
            print 'CRITICAL'
        else:
            print 'UNKOWN'

        print 'BINARY_PATH_NAME  : %s' % resp['lpServiceConfig']['lpBinaryPathName'][:-1]
        print 'LOAD_ORDER_GROUP  : %s' % resp['lpServiceConfig']['lpLoadOrderGroup'][:-1]
        print 'TAG               : %d' % resp['lpServiceConfig']['dwTagId']
        print 'DISPLAY_NAME      : %s' % resp['lpServiceConfig']['lpDisplayName'][:-1]
        print 'DEPENDENCIES      : %s' % resp['lpServiceConfig']['lpDependencies'][:-1]
        print 'SERVICE_START_NAME: %s' % resp['lpServiceConfig']['lpServiceStartName'][:-1]

    def __scmr_parse_state(self, state):
        if state == scmr.SERVICE_CONTINUE_PENDING:
           return 'CONTINUE PENDING'
        elif state == scmr.SERVICE_PAUSE_PENDING:
           return 'PAUSE PENDING'
        elif state == scmr.SERVICE_PAUSED:
           return 'PAUSED'
        elif state == scmr.SERVICE_RUNNING:
           return 'RUNNING'
        elif state == scmr.SERVICE_START_PENDING:
           return 'START PENDING'
        elif state == scmr.SERVICE_STOP_PENDING:
           return 'STOP PENDING'
        elif state == scmr.SERVICE_STOPPED:
           return 'STOPPED'
        else:
           return 'UNKOWN'

    def __scmr_state(self, srvname, return_state=False):
        '''
        Display state of a service
        '''
        logger.info('Querying the state of service %s' % srvname)

        resp = scmr.hRQueryServiceStatus(self.__rpc, self.__service_handle)
        state = resp['lpServiceStatus']['dwCurrentState']

        if return_state:
            return self.__scmr_parse_state(state)
        else:
            print 'Service %s state is: %s' % (srvname, self.__scmr_parse_state(state))

    def __scmr_config(self, srvname, return_answer=False):
        '''
        Display a service configuration
        '''
        logger.info('Querying the service configuration of service %s' % srvname)

        resp = scmr.hRQueryServiceConfigW(self.__rpc, self.__service_handle)

        if return_answer:
            return resp

        print 'Service %s information:' % srvname
        self.__scmr_parse_config(resp)

    def __scmr_start(self, srvname, srvargs=''):
        '''
        Start the service
        '''
        logger.info('Starting the service %s' % srvname)

        if srvargs:
            srvargs = str(srvargs).split(' ')
        else:
            srvargs = []

        scmr.hRStartServiceW(self.__rpc, self.__service_handle, argc=len(srvargs), argv=srvargs)
        self.__scmr_state(srvname)

    def __scmr_stop(self, srvname):
        '''
        Stop the service
        '''
        logger.info('Stopping the service %s' % srvname)

        scmr.hRControlService(self.__rpc, self.__service_handle, scmr.SERVICE_CONTROL_STOP)
        self.__scmr_state(srvname)

    def __scmr_change(self, display=None, path=None, service_type=None, start_type=None, start_name=None, password=None):
        '''
        Change the configuration of a service
        '''
        if start_type is not None:
            start_type = int(start_type)
        else:
            start_type = scmr.SERVICE_NO_CHANGE

        if service_type is not None:
            service_type = int(service_type)
        else:
            service_type = scmr.SERVICE_NO_CHANGE

        if display is not None:
            display = '%s\x00' % display
        else:
            display = NULL

        if path is not None:
            path = '%s\x00' % path
        else:
            path = NULL

        if start_name is not None:
            start_name = '%s\x00' % start_name
        else:
            start_name = NULL

        if password is not None:
            s = self.trans.get_smb_connection()
            key = s.getSessionKey()
            password = ('%s\x00' % password).encode('utf-16le')
            password = encryptSecret(key, password)
        else:
            password = NULL

        scmr.hRChangeServiceConfigW(self.__rpc, self.__service_handle, service_type, start_type, scmr.SERVICE_ERROR_IGNORE, path, NULL, NULL, NULL, 0, start_name, password, 0, display)

    def __scmr_list_parse(self, srvname, resp):
        '''
        Parse list of services
        '''
        services = []

        for i in range(len(resp)):
            name = resp[i]['lpServiceName'][:-1]
            display = resp[i]['lpDisplayName'][:-1]
            state = resp[i]['ServiceStatus']['dwCurrentState']

            if srvname:
                srvname = srvname.strip('*')

                if srvname.lower() not in display.lower() and srvname.lower() not in name.lower():
                    continue

            services.append((display, name, state))

        services.sort()

        for service in services:
            print '%s (%s): %-80s' % (service[0], service[1], self.__scmr_parse_state(service[2]))

        return len(services)

    def __scmr_list(self, srvname):
        '''
        List services
        '''
        logger.info('Listing services')

        resp = scmr.hREnumServicesStatusW(self.__rpc, self.__mgr_handle, dwServiceState=scmr.SERVICE_STATE_ALL)
        num = self.__scmr_list_parse(srvname, resp)

        print '\nTotal services: %d\n' % num
