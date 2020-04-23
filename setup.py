#!/usr/bin/env python
# -*- coding: iso-8859-15 -*-
# -*- Mode: python -*-

'''
$Id$

keimpx is an open source tool, released under the Apache
License 2.0. It is developed in Python using SecureAuth Corporations's
Impacket library, https://github.com/SecureAuthCorp/impacket.

It can be used to quickly check for the usefulness of credentials across a
network over SMB.

Homepage:                   https://nccgroup.github.io/keimpx/
Usage:                      https://github.com/nccgroup/keimpx#usage
Examples:                   https://github.com/nccgroup/keimpx/wiki/Examples
Frequently Asked Questions: https://github.com/nccgroup/keimpx/wiki/FAQ
Contributors:               https://github.com/nccgroup/keimpx#contributors

License:

Copyright 2009-2020 Bernardo Damele A. G. bernardo.damele@gmail.com

Licensed under the Apache License, Version 2.0 (the "License"); you may not use this file except in compliance with the
License. You may obtain a copy of the License at

http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software distributed under the License is distributed on an
"AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the License for the
specific language governing permissions and limitations under the License.

This product includes software developed by SecureAuth Corporation
(https://www.secureauth.com/).
'''

from distutils.core import setup

setup(
    name="keimpx",
    version="0.5.1-rc",
    description="keimpx: check for the usefulness of credentials across a network over SMB",
    author="Bernardo Damele A. G.",
    author_email="bernardo.damele@gmail.com",
    url="https://github.com/nccgroup/keimpx",
    license="Modified Apache license",
    console=["keimpx.py"],
    data_files=[
        ("contrib", ["contrib\\srv_bindshell.exe", ]),
    ]
)
