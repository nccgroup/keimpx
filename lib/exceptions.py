#!/usr/bin/env python
# -*- coding: iso-8859-15 -*-
# -*- Mode: python -*-

class keimpxError(Exception):
    pass

class credentialsError(keimpxError):
    pass

class domainError(keimpxError):
    pass

class targetError(keimpxError):
    pass

class threadError(keimpxError):
    pass

class missingOption(keimpxError):
    pass

class missingService(keimpxError):
    pass

class missingShare(keimpxError):
    pass

class missingFile(keimpxError):
    pass

class registryKey(keimpxError):
    pass

class missingPermission(keimpxError):
    pass
