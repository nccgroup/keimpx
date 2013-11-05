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
        self.__svcctl_connect()
        self.__svcctl_list(srvname)
        self.__svcctl_disconnect()

    def status(self, srvname):
        self.__svcctl_connect()
        self.__svcctl_srv_manager(srvname)
        self.__svcctl_status(srvname)
        self.__svcctl_disconnect()

    def query(self, srvname):
        self.__svcctl_connect()
        self.__svcctl_srv_manager(srvname)
        self.__svcctl_config(srvname)
        self.__svcctl_disconnect()

    def start(self, srvname, srvargs=''):
        self.__svcctl_connect()
        self.__svcctl_srv_manager(srvname)
        self.__svcctl_start(srvname, srvargs)
        self.__svcctl_disconnect(srvname)

    def stop(self, srvname):
        self.__svcctl_connect()
        self.__svcctl_srv_manager(srvname)
        self.__svcctl_stop(srvname)
        self.__svcctl_disconnect(srvname)

    def change(self, srvname):
        self.__svcctl_connect()
        self.__svcctl_srv_manager(srvname)
        self.__svcctl_change(srvname)
        self.__svcctl_disconnect(srvname)

    def deploy(self, srvname, local_file=None, srvargs='', remote_file=None, displayname=None):
        self.__oldpwd = self.pwd
        self.pwd = '\\'

        self.__svcctl_bin_upload(local_file, remote_file)
        self.__svcctl_connect()
        self.__svcctl_create(srvname, remote_file, displayname)
        self.__svcctl_srv_manager(srvname)
        self.__svcctl_start(srvname, srvargs)
        self.__svcctl_disconnect(srvname)

        self.pwd = self.__oldpwd

    def undeploy(self, srvname):
        self.__oldpwd = self.pwd
        self.pwd = '\\'

        self.__svcctl_connect()
        self.__svcctl_srv_manager(srvname)
        resp = self.__svc.QueryServiceConfigW(self.__svc_handle)
        remote_file = resp['QueryConfig']['BinaryPathName'].decode('utf-16le')
        remote_file = str(os.path.basename(remote_file.replace('\\', '/')))

        if self.__svcctl_status(srvname, return_status=True) == 'RUNNING':
            self.__svcctl_stop(srvname)

        self.__svcctl_delete(srvname)
        self.__svcctl_disconnect(srvname)
        self.__svcctl_bin_remove(remote_file)
        self.pwd = self.__oldpwd

    def svcshell(self, mode='SHARE'):
        self.__svcctl_connect()

        try:
            if mode == 'SERVER':
                serverThread = SMBServer()
                serverThread.daemon = True
                serverThread.start()

            self.shell = SvcShell(self.__svc, self.__mgr_handle, self.trans, mode)
            self.shell.cmdloop()

            if mode == 'SERVER':
                serverThread.stop()
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
        self.__svcctl_disconnect()

    def __svcctl_srv_manager(self, srvname):
        self.__resp = self.__svc.OpenServiceW(self.__mgr_handle, srvname.encode('utf-16le'))
        self.__svc_handle = self.__resp['ContextHandle']

    def __svcctl_connect(self):
        '''
        Connect to svcctl named pipe
        '''
        logger.debug('Connecting to the SVCCTL named pipe')
        self.smb_transport('svcctl')

        logger.debug('Binding on Services Control Manager (SCM) interface')
        self.__dce = self.trans.get_dce_rpc()
        self.__dce.bind(svcctl.MSRPC_UUID_SVCCTL)
        self.__svc = svcctl.DCERPCSvcCtl(self.__dce)
        self.__resp = self.__svc.OpenSCManagerW()
        self.__mgr_handle = self.__resp['ContextHandle']

    def __svcctl_disconnect(self, srvname=None):
        '''
        Disconnect from svcctl named pipe
        '''
        logger.debug('Disconnecting from the SVCCTL named pipe')

        if srvname:
            self.__svc.CloseServiceHandle(self.__svc_handle)

        if self.__mgr_handle:
            self.__svc.CloseServiceHandle(self.__mgr_handle)

        self.__dce.disconnect()

    def __svcctl_bin_upload(self, local_file, remote_file):
        '''
        Upload the service executable
        '''
        self.use(default_share)
        self.__pathname = ntpath.join(default_share, remote_file)
        logger.info('Uploading the service executable to %s' % self.__pathname)
        self.upload(local_file, remote_file)

    def __svcctl_bin_remove(self, remote_file):
        '''
        Remove the service executable
        '''
        self.use(default_share)
        self.__pathname = ntpath.join(default_share, remote_file)
        logger.info('Removing the service executable %s' % self.__pathname)
        self.rm(remote_file)

    def __svcctl_create(self, srvname, remote_file, displayname=None):
        '''
        Create the service
        '''
        logger.info('Creating the service %s' % srvname)

        if not displayname:
            displayname = srvname

        self.__pathname = ntpath.join('%SystemRoot%', remote_file)
        self.__pathname = self.__pathname.encode('utf-16le')
        self.__svc.CreateServiceW(self.__mgr_handle, srvname.encode('utf-16le'), displayname.encode('utf-16le'), self.__pathname)

    def __svcctl_delete(self, srvname):
        '''
        Delete the service
        '''
        logger.info('Deleting the service %s' % srvname)
        self.__svc.DeleteService(self.__svc_handle)

    def __svcctl_parse_config(self, resp):
        print 'TYPE              : %2d - ' % resp['QueryConfig']['ServiceType'],

        if resp['QueryConfig']['ServiceType'] & 0x1:
            print 'SERVICE_KERNLE_DRIVER'
        if resp['QueryConfig']['ServiceType'] & 0x2:
            print 'SERVICE_FILE_SYSTEM_DRIVER'
        if resp['QueryConfig']['ServiceType'] & 0x10:
            print 'SERVICE_WIN32_OWN_PROCESS'
        if resp['QueryConfig']['ServiceType'] & 0x20:
            print 'SERVICE_WIN32_SHARE_PROCESS'
        if resp['QueryConfig']['ServiceType'] & 0x100:
            print 'SERVICE_INTERACTIVE_PROCESS'

        print 'START_TYPE        : %2d - ' % resp['QueryConfig']['StartType'],

        if resp['QueryConfig']['StartType'] == 0x0:
            print 'BOOT START'
        elif resp['QueryConfig']['StartType'] == 0x1:
            print 'SYSTEM START'
        elif resp['QueryConfig']['StartType'] == 0x2:
            print 'AUTO START'
        elif resp['QueryConfig']['StartType'] == 0x3:
            print 'DEMAND START'
        elif resp['QueryConfig']['StartType'] == 0x4:
            print 'DISABLED'
        else:
            print 'UNKOWN'

        print 'ERROR_CONTROL     : %2d - ' % resp['QueryConfig']['ErrorControl'],

        if resp['QueryConfig']['ErrorControl'] == 0x0:
            print 'IGNORE'
        elif resp['QueryConfig']['ErrorControl'] == 0x1:
            print 'NORMAL'
        elif resp['QueryConfig']['ErrorControl'] == 0x2:
            print 'SEVERE'
        elif resp['QueryConfig']['ErrorControl'] == 0x3:
            print 'CRITICAL'
        else:
            print 'UNKOWN'

        print 'BINARY_PATH_NAME  : %s' % resp['QueryConfig']['BinaryPathName'].decode('utf-16le')
        print 'LOAD_ORDER_GROUP  : %s' % resp['QueryConfig']['LoadOrderGroup'].decode('utf-16le')
        print 'TAG               : %d' % resp['QueryConfig']['TagID']
        print 'DISPLAY_NAME      : %s' % resp['QueryConfig']['DisplayName'].decode('utf-16le')
        print 'DEPENDENCIES      : %s' % resp['QueryConfig']['Dependencies'].decode('utf-16le').replace('/', ' - ')
        print 'SERVICE_START_NAME: %s' % resp['QueryConfig']['ServiceStartName'].decode('utf-16le')

    def __svcctl_parse_status(self, status):
        if status == svcctl.SERVICE_CONTINUE_PENDING:
           return 'CONTINUE PENDING'
        elif status == svcctl.SERVICE_PAUSE_PENDING:
           return 'PAUSE PENDING'
        elif status == svcctl.SERVICE_PAUSED:
           return 'PAUSED'
        elif status == svcctl.SERVICE_RUNNING:
           return 'RUNNING'
        elif status == svcctl.SERVICE_START_PENDING:
           return 'START PENDING'
        elif status == svcctl.SERVICE_STOP_PENDING:
           return 'STOP PENDING'
        elif status == svcctl.SERVICE_STOPPED:
           return 'STOPPED'
        else:
           return 'UNKOWN'

    def __svcctl_status(self, srvname, return_status=False):
        '''
        Display status of a service
        '''
        logger.info('Querying the status of service %s' % srvname)

        ans = self.__svc.QueryServiceStatus(self.__svc_handle)
        status = ans['CurrentState']

        if return_status:
            return self.__svcctl_parse_status(status)
        else:
            print 'Service %s status is: %s' % (srvname, self.__svcctl_parse_status(status))

    def __svcctl_config(self, srvname):
        '''
        Display a service configuration
        '''
        logger.info('Querying the service configuration of service %s' % srvname)

        print 'Service %s information:' % srvname

        resp = self.__svc.QueryServiceConfigW(self.__svc_handle)
        self.__svcctl_parse_config(resp)

    def __svcctl_start(self, srvname, srvargs=''):
        '''
        Start the service
        '''
        logger.info('Starting the service %s' % srvname)

        if not srvargs:
            srvargs = []
        else:
            new_srvargs = []

            for arg in str(srvargs).split(' '):
                new_srvargs.append(arg.encode('utf-16le'))

            srvargs = new_srvargs

        self.__svc.StartServiceW(self.__svc_handle, srvargs)
        self.__svcctl_status(srvname)

    def __svcctl_stop(self, srvname):
        '''
        Stop the service
        '''
        logger.info('Stopping the service %s' % srvname)

        self.__svc.StopService(self.__svc_handle)
        self.__svcctl_status(srvname)

    def __svcctl_change(self, srvname):
        '''
        Change the configuration of a service
        '''
        # TODO
        self.__svc.ChangeServiceConfigW(self.__svc_handle, display, path, service_type, start_type, start_name, password)

    def __svcctl_list_parse(self, srvname, resp):
        '''
        Parse list of services
        '''
        services = []

        for i in range(len(resp)):
            name = resp[i]['ServiceName'].decode('utf-16')
            display = resp[i]['DisplayName'].decode('utf-16')
            state = resp[i]['CurrentState']

            if srvname:
                srvname = srvname.strip('*')

                if srvname.lower() not in display.lower() and srvname.lower() not in name.lower():
                    continue

            services.append((display, name, state))

        services.sort()

        for service in services:
            print '%s (%s): %-80s' % (service[0], service[1], self.__svcctl_parse_status(service[2]))

        return len(services)

    def __svcctl_list(self, srvname):
        '''
        List services
        '''
        logger.info('Listing services')

        #resp = self.__svc.EnumServicesStatusW(self.__mgr_handle, serviceType=svcctl.SERVICE_WIN32_SHARE_PROCESS)
        #resp = self.__svc.EnumServicesStatusW(self.__mgr_handle, serviceType=svcctl.SERVICE_WIN32_OWN_PROCESS)
        #resp = self.__svc.EnumServicesStatusW(self.__mgr_handle, serviceType=svcctl.SERVICE_FILE_SYSTEM_DRIVER)
        #resp = self.__svc.EnumServicesStatusW(self.__mgr_handle, serviceType=svcctl.SERVICE_INTERACTIVE_PROCESS)
        #resp = self.__svc.EnumServicesStatusW(self.__mgr_handle, serviceType=svcctl.SERVICE_WIN32_OWN_PROCESS | svcctl.SERVICE_WIN32_SHARE_PROCESS | svcctl.SERVICE_INTERACTIVE_PROCESS, serviceState=svcctl.SERVICE_STATE_ALL)
        resp = self.__svc.EnumServicesStatusW(self.__mgr_handle, serviceState=svcctl.SERVICE_STATE_ALL)
        num = self.__svcctl_list_parse(srvname, resp)

        print '\nTotal services: %d\n' % num
