#!/usr/bin/env python
# -*- coding: iso-8859-15 -*-
# -*- Mode: python -*-

'''
$Id$

keimpx is an open source tool, released under a modified version of Apache
License 1.1. It is developed in Python using SecureAuth Corporations's Impacket
library.

It can be used to quickly check for the usefulness of credentials across a
network over SMB.

Homepage:                   https://github.com/inquisb/keimpx
Usage:                      https://github.com/inquisb/keimpx#usage
Examples:                   http://code.google.com/p/keimpx/wiki/Examples
Frequently Asked Questions: http://code.google.com/p/keimpx/wiki/FAQ
Contributors:               https://github.com/inquisb/keimpx#contributors

License:

I provide this software under a slightly modified version of the
Apache Software License. The only changes to the document were the
replacement of "Apache" with "keimpx" and "Apache Software Foundation"
with "Bernardo Damele A. G.". Feel free to compare the resulting document
to the official Apache license.

The `Apache Software License' is an Open Source Initiative Approved
License.

The Apache Software License, Version 1.1
Modifications by Bernardo Damele A. G. (see above)

Copyright (c) 2019 Bernardo Damele A. G. <bernardo.damele@gmail.com>
All rights reserved.

This product includes software developed by SecureAuth Corporation
(https://www.secureauth.com/).

THIS SOFTWARE IS PROVIDED ``AS IS'' AND ANY EXPRESSED OR IMPLIED
WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES
OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
DISCLAIMED.  IN NO EVENT SHALL Bernardo Damele A. G. OR
ITS CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF
USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND
ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY,
OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT
OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
SUCH DAMAGE.
'''

from distutils.core import setup

setup(
    name="keimpx",
    version="0.4",
    description="keimpx: check for the usefulness of credentials across a network over SMB",
    author="Bernardo Damele A. G.",
    author_email="bernardo.damele@gmail.com",
    url="https://github.com/inquisb/keimpx",
    license="Modified Apache license",
    console=["keimpx.py"],
    data_files=[
        ("contrib", ["contrib\\srv_bindshell.exe", ]),
    ]
)
