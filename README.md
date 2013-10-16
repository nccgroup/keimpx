# Introduction

keimpx is an open source tool, released under a modified version of Apache License 1.1.

It can be used to quickly check for valid credentials across a network over SMB. Credentials can be:

* Combination of **user / plain-text password**.
* Combination of **user / NTLM hash**.
* Combination of **user / NTLM logon session token**.

If any valid credentials has been discovered across the network after its attack phase, the user is asked to choose which host to connect to and which valid credentials to use, then he will be prompted with an **interactive SMB shell** where the user can:

* Spawn an interactive command prompt.
* Navigate through the remote SMB shares: list, upload, download files, create, remove files, etc.
* Deploy and undeploy his own service, for instance, a backdoor listening on a TCP port for incoming connections.
* List users details, domains and password policy.
* More to come, see the [issues](https://github.com/inquisb/keimpx/issues) page.

## Dependencies

It is developed in [Python](http://www.python.org) using CORE Impact's [Impacket](http://code.google.com/p/impacket/) library: **you need to install the latest development version from its Google Code subversion repository** otherwise keimpx won't work. This Python library requires also [PyCrypto](http://www.dlitz.net/software/pycrypto/) to work. If you want to run keimpx on Windows, you might find useful the prebuilt [PyCrypto binaries](http://www.voidspace.org.uk/python/modules.shtml#pycrypto).

## Usage

Let's say you are performing an infrastructure penetration test of a large network, you 
[owned](http://metasploit.com/) a Windows workstation, [escalated](http://corelabs.coresecurity.com/index.php?module=Wiki&action=view&type=tool&name=Pass-The-Hash_Toolkit) [your](http://www.mwrinfosecurity.com/publications/mwri_security-implications-of-windows-access-tokens_2008-04-14.pdf) [privileges](http://technet.microsoft.com/en-us/sysinternals/bb664922.aspx) to `Administrator` or `LOCAL SYSTEM` and [dumped password hashes](http://bernardodamele.blogspot.com/search/label/dump).

You also enumerated the list of machines within the Windows domain via `net` command, ping sweep, ARP scan and network traffic sniffing.

Now, what if you want to check for the validity of the dumped hashes **without the need to crack them** across the whole Windows network over SMB? What if you want to login to one or more system using the dumped NTLM hashes then surf the shares or even spawn a command prompt?

**Fire up keimpx and let it do the work for you!**

Another scenario where it comes handy is discussed in [this blog post](http://bernardodamele.blogspot.com/2009/11/abuse-citrix-and-own-domain.html).

## Help message

        keimpx 0.3-dev
        by Bernardo Damele A. G. <bernardo.damele@gmail.com>
        
    Usage: keimpx.py [options]

    Options:
      --version       show program's version number and exit
      -h, --help      show this help message and exit
      -v VERBOSE      Verbosity level: 0-2 (default: 0)
      -t TARGET       Target address
      -l LIST         File with list of targets
      -U USER         User
      -P PASSWORD     Password
      --nt=NTHASH     NT hash
      --lm=LMHASH     LM hash
      -c CREDSFILE    File with list of credentials
      -D DOMAIN       Domain
      -d DOMAINSFILE  File with list of domains
      -p PORT         SMB port: 139 or 445 (default: 445)
      -n NAME         Local hostname
      -T THREADS      Maximum simultaneous connections (default: 10)
      -b              Batch mode: do not ask to get an interactive SMB shell
      -x EXECUTELIST  Execute a list of commands against all hosts

For examples see [this wiki page](https://github.com/inquisb/keimpx/wiki/Examples).

## Frequently Asked Questions

See [this wiki page](https://github.com/inquisb/keimpx/wiki/FAQ).

## License

I provide this software under a slightly modified version of the Apache Software License. The only changes to the document were the replacement of "Apache" with "keimpx" and "Apache Software Foundation" with "Bernardo Damele A. G.". Feel free to compare the resulting document to the official Apache license.

The `Apache Software License' is an Open Source Initiative Approved License.

The Apache Software License, Version 1.1
Modifications by Bernardo Damele A. G. (see above)

Copyright (c) 2009-2013 Bernardo Damele A. G. <bernardo.damele@gmail.com>
All rights reserved.

This product includes software developed by CORE Security Technologies
(http://www.coresecurity.com/).

THIS SOFTWARE IS PROVIDED ``AS IS'' AND ANY EXPRESSED OR IMPLIED
WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES
OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
DISCLAIMED.  IN NO EVENT SHALL THE APACHE SOFTWARE FOUNDATION OR
ITS CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF
USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND
ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY,
OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT
OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
SUCH DAMAGE.

## Contributors

Thanks to:

* [deanx](mailto:deanx@65535.com) - for developing [polenum](http://labs.portcullis.co.uk/application/polenum/) tool and some classes ripped from him.
* [frego](mailto:frego@0x3f.net) - for his Windows service bind-shell executable and help with the service deploy/undeploy methods.
* [gera](mailto:gera@coresecurity.com), [beto](mailto:bethus@gmail.com) and the rest of the [CORE Security](http://corelabs.coresecurity.com) guys - for developing such amazing Python [library](http://code.google.com/p/impacket/) and providing it with [examples](http://code.google.com/p/impacket/source/browse/#svn%2Ftrunk%2Fexamples).
