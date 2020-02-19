# Introduction

keimpx is an open source tool, released under the Apache License 2.0.

It can be used to quickly check for valid credentials across a network over SMB. Credentials can be:

* Combination of **user / plain-text password**.
* Combination of **user / NTLM hash**.
* Combination of **user / NTLM logon session token**.

If any valid credentials are discovered across the network after its attack phase, the user is asked to choose which host to connect to and which valid credentials to use. They will then be provided with an **interactive SMB shell** where the user can:

* Spawn an interactive command prompt.
* Navigate through the remote SMB shares: list, upload, download files, create, remove files, etc.
* Deploy and undeploy their own services, for instance, a backdoor listening on a TCP port for incoming connections.
* List users details, domains and password policy.
* More to come, see the [issues](https://github.com/nccgroup/keimpx/issues) page.

## Dependencies

keimpx is currently developed using [Python 3.7](https://www.python.org/) and makes use of the excellent [Impacket](https://github.com/SecureAuthCorp/impacket) library from [SecureAuth Corporation](https://www.secureauth.com/) for much of its functionality. keimpx also makes use of the [PyCryptodome](https://github.com/Legrandin/pycryptodome) library for cryptographic functions.

## Installation

To install keimpx, first install Python 3.7. On Windows, you can find the installer at this [link](https://www.python.org/downloads/release/python-376/). For Linux users, many distributions provide Python 3 and make it available via your package manager (usual package names include python3 and python).

On Linux systems, you may also need to install pip and openssl-dev using your package manager for the next step.

Once you have Python 3.7 installed, use pip to install the required dependencies using this command:
```python
pip install -r requirements.txt
```
keimpx can then be executed by running on Linux systems:
```bash
./keimpx.py [options]
```
Or if this doesn't work:
```bash
python keimpx.py [options]
python3 keimpx.py [options]
```

On Windows systems, you may need to specify the full path to your Python 3.7 binary, for example:
```
C:\Python37\bin\python.exe keimpx.py [options]
```
Please ensure you use the correct path for your system, as this is only an example.

## Usage

Let's say you are performing an infrastructure penetration test of a large network, you 
[owned](http://metasploit.com/) a Windows workstation, escalated your [privileges](http://technet.microsoft.com/en-us/sysinternals/bb664922.aspx) to `Administrator` or `LOCAL SYSTEM` and [dumped password hashes](http://bernardodamele.blogspot.com/search/label/dump).

You also enumerated the list of machines within the Windows domain via `net` command, ping sweep, ARP scan and network traffic sniffing.

Now, what if you want to check for the validity of the dumped hashes **without the need to crack them** across the whole Windows network over SMB? What if you want to login to one or more system using the dumped NTLM hashes then surf the shares or even spawn a command prompt?

**Fire up keimpx and let it do the work for you!**

Another scenario where it comes handy is discussed in [this blog post](http://bernardodamele.blogspot.com/2009/11/abuse-citrix-and-own-domain.html).

## Help message

    keimpx 0.5-beta.3
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

For examples see [this wiki page](https://github.com/nccgroup/keimpx/wiki/Examples).

## Frequently Asked Questions

See [this wiki page](https://github.com/nccgroup/keimpx/wiki/FAQ).

## License

Copyright 2009-2020 Bernardo Damele A. G. <bernardo.damele@gmail.com>

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.

## Contributors

Thanks to:

* [deanx](mailto:deanx@65535.com) - for developing [polenum](http://labs.portcullis.co.uk/application/polenum/) and some classes ripped from him.
* [Wh1t3Fox](https://github.com/Wh1t3Fox) - for updating [polenum](https://github.com/Wh1t3Fox) to make it compatible with newer versions of Impacket.
* [frego](mailto:frego@0x3f.net) - for his Windows service bind-shell executable and help with the service deploy/undeploy methods.
* [gera](mailto:gera@coresecurity.com), [beto](mailto:bethus@gmail.com) and the rest of the [SecureAuth Corporation](https://www.secureauth.com/) guys - for developing such amazing Python [library](https://github.com/SecureAuthCorp/impacket) and providing it with [examples](https://github.com/SecureAuthCorp/impacket/tree/master/examples).
* [NEXUS2345](https://github.com/nexus2345) - for updating and maintaining keimpx.
