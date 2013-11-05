#!/usr/bin/env python
# -*- coding: iso-8859-15 -*-
# -*- Mode: python -*-

from lib.common import *

########################################################################
# Code ripped with permission from deanx's polenum tool,               #
# http://labs.portcullis.co.uk/application/polenum/                    #
########################################################################
def get_obj(name):
    return eval(name)

def d2b(a):
    bin = []

    while a:
        bin.append(a%2)
        a /= 2

    return bin[::-1]

def display_time(filetime_high, filetime_low, minutes_utc=0):
    import __builtins__
    d = filetime_low + (filetime_high)*16**8 # convert to 64bit int
    d *= 1.0e-7 # convert to seconds
    d -= 11644473600 # remove 3389 years?

    try:
        return strftime('%a, %d %b %Y %H:%M:%S +0000ddddd', localtime(d)) # return the standard format day
    except ValueError, e:
        return '0'

class ExtendInplace(type):
    def __new__(self, name, bases, dict):
        prevclass = get_obj(name)
        del dict['__module__']
        del dict['__metaclass__']

        # We can't use prevclass.__dict__.update since __dict__
        # isn't a real dict
        for k, v in dict.iteritems():
            setattr(prevclass, k, v)

        return prevclass

def convert(low, high, no_zero):
    if low == 0 and hex(high) == '-0x80000000':
        return 'Not Set'
    if low == 0 and high == 0:
        return 'None'
    if no_zero: # make sure we have a +ve vale for the unsined int
        if (low != 0):
            high = 0 - (high+1)
        else:
            high = 0 - (high)
        low = 0 - low

    tmp = low + (high)*16**8 # convert to 64bit int
    tmp *= (1e-7) #  convert to seconds

    try:
        minutes = int(strftime('%M', gmtime(tmp)))  # do the conversion to human readable format
    except ValueError, e:
        return 'BAD TIME:'

    hours = int(strftime('%H', gmtime(tmp)))
    days = int(strftime('%j', gmtime(tmp)))-1
    time = ''

    if days > 1:
     time = str(days) + ' days '
    elif days == 1:
        time = str(days) + ' day '
    if hours > 1:
        time += str(hours) + ' hours '
    elif hours == 1:
        time = str(days) + ' hour '    
    if minutes > 1:
        time += str(minutes) + ' minutes'
    elif minutes == 1:
        time = str(days) + ' minute '

    return time

class MSRPCPassInfo:
    PASSCOMPLEX = {
                    5: 'Domain Password Complex',
                    4: 'Domain Password No Anon Change',
                    3: 'Domain Password No Clear Change',
                    2: 'Domain Password Lockout Admins',
                    1: 'Domain Password Store Cleartext',
                    0: 'Domain Refuse Password Change'
                  }

    def __init__(self, data = None):
        self._min_pass_length = 0
        self._pass_hist = 0
        self._pass_prop= 0
        self._min_age_low = 0
        self._min_age_high = 0
        self._max_age_low = 0
        self._max_age_high = 0
        self._pwd_can_change_low = 0
        self._pwd_can_change_high = 0
        self._pwd_must_change_low = 0
        self._pwd_must_change_high = 0
        self._max_force_low = 0
        self._max_force_high = 0
        self._role = 0
        self._lockout_window_low = 0
        self._lockout_window_high = 0
        self._lockout_dur_low = 0
        self._lockout_dur_high = 0
        self._lockout_thresh = 0

        if data:
            self.set_header(data, 1)

    def set_header(self,data,level):
        index = 8

        if level == 1: 
            self._min_pass_length, self._pass_hist, self._pass_prop, self._max_age_low, self._max_age_high, self._min_age_low, self._min_age_high = unpack('<HHLllll',data[index:index+24])
            bin = d2b(self._pass_prop)

            if len(bin) != 8:
                for x in xrange(6 - len(bin)):
                    bin.insert(0,0)

            self._pass_prop =  ''.join([str(g) for g in bin])    

        if level == 3:
            self._max_force_low, self._max_force_high = unpack('<ll',data[index:index+8])
        elif level == 7:
            self._role = unpack('<L',data[index:index+4])
        elif level == 12:
            self._lockout_dur_low, self._lockout_dur_high, self._lockout_window_low, self._lockout_window_high, self._lockout_thresh = unpack('<llllH',data[index:index+18])

    def print_friendly(self):
        print 'Minimum password length: %s' % str(self._min_pass_length or 'None')
        print 'Password history length: %s' % str(self._pass_hist or 'None' )
        print 'Maximum password age: %s' % str(convert(self._max_age_low, self._max_age_high, 1))
        print 'Password Complexity Flags: %s' % str(self._pass_prop or 'None')
        print 'Minimum password age: %s' % str(convert(self._min_age_low, self._min_age_high, 1))
        print 'Reset Account Lockout Counter: %s' % str(convert(self._lockout_window_low,self._lockout_window_high, 1)) 
        print 'Locked Account Duration: %s' % str(convert(self._lockout_dur_low,self._lockout_dur_high, 1)) 
        print 'Account Lockout Threshold: %s' % str(self._lockout_thresh or 'None')
        print 'Forced Log off Time: %s' % str(convert(self._max_force_low, self._max_force_high, 1))

        i = 0

        for a in self._pass_prop:
            print '%s: %s' % (self.PASSCOMPLEX[i], str(a))

            i+= 1

        return

class SAMREnumDomainsPass(ImpactPacket.Header):
    OP_NUM = 0x2E

    __SIZE = 22

    def __init__(self, aBuffer = None):
        ImpactPacket.Header.__init__(self, SAMREnumDomainsPass.__SIZE)

        if aBuffer:
            self.load_header(aBuffer)

    def get_context_handle(self):
        return self.get_bytes().tolist()[:20]

    def set_context_handle(self, handle):
        assert 20 == len(handle)
        self.get_bytes()[:20] = array.array('B', handle)

    def get_resume_handle(self):
        return self.get_long(20, '<')

    def set_resume_handle(self, handle):
        self.set_long(20, handle, '<')

    def get_account_control(self):
        return self.get_long(20, '<')

    def set_account_control(self, mask):
        self.set_long(20, mask, '<')

    def get_pref_max_size(self):
        return self.get_long(28, '<')

    def set_pref_max_size(self, size):
        self.set_long(28, size, '<')

    def get_header_size(self):
        return SAMREnumDomainsPass.__SIZE

    def get_level(self):
        return self.get_word(20, '<')

    def set_level(self, level):
        self.set_word(20, level, '<')

class SAMRRespLookupPassPolicy(ImpactPacket.Header):
    __SIZE = 4

    def __init__(self, aBuffer = None):
        ImpactPacket.Header.__init__(self, SAMRRespLookupPassPolicy.__SIZE)

        if aBuffer:
            self.load_header(aBuffer)

    def get_pass_info(self):
        return MSRPCPassInfo(self.get_bytes()[:-4].tostring())

    def set_pass_info(self, info, level):
        assert isinstance(info, MSRPCPassInfo)
        self.get_bytes()[:-4] = array.array('B', info.rawData())

    def get_return_code(self):
        return self.get_long(-4, '<')

    def set_return_code(self, code):
        self.set_long(-4, code, '<')

    def get_context_handle(self):
        return self.get_bytes().tolist()[:12]

    def get_header_size(self):
        var_size = len(self.get_bytes()) - SAMRRespLookupPassPolicy.__SIZE
        assert var_size > 0

        return SAMRRespLookupPassPolicy.__SIZE + var_size

class DCERPCSamr:
    __metaclass__ = ExtendInplace

    def enumpswpolicy(self,context_handle): # needs to make 3 requests to get all pass policy
        enumpas = SAMREnumDomainsPass()
        enumpas.set_context_handle(context_handle)
        enumpas.set_level(1)
        self._dcerpc.send(enumpas)
        data = self._dcerpc.recv()

        retVal = SAMRRespLookupPassPolicy(data)
        pspol = retVal.get_pass_info()
        enumpas = SAMREnumDomainsPass()
        enumpas.set_context_handle(context_handle)
        enumpas.set_level(3)
        self._dcerpc.send(enumpas)
        data = self._dcerpc.recv()
        pspol.set_header(data,3)

        enumpas = SAMREnumDomainsPass()
        enumpas.set_context_handle(context_handle)
        enumpas.set_level(7)
        self._dcerpc.send(enumpas)
        data = self._dcerpc.recv()
        pspol.set_header(data,7)

        enumpas = SAMREnumDomainsPass()
        enumpas.set_context_handle(context_handle)
        enumpas.set_level(12)
        self._dcerpc.send(enumpas)
        data = self._dcerpc.recv()
        pspol.set_header(data,12)

        return pspol 

    def opendomain(self, context_handle, domain_sid):
        opendom = SAMROpenDomainHeader()
        opendom.set_access_mask(0x305)
        opendom.set_context_handle(context_handle)
        opendom.set_domain_sid(domain_sid)
        self._dcerpc.send(opendom)
        data = self._dcerpc.recv()
        retVal = SAMRRespOpenDomainHeader(data)

        return retVal
