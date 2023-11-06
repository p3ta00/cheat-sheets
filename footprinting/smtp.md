# Metasploit
```
[msf](Jobs:0 Agents:0) >> search smtp_enum
​
Matching Modules
================
​
   #  Name                              Disclosure Date  Rank    Check  Description
   -  ----                              ---------------  ----    -----  -----------
   0  auxiliary/scanner/smtp/smtp_enum                   normal  No     SMTP User Enumeration Utility
​
​
Interact with a module by name or index. For example info 0, use 0 or use auxiliary/scanner/smtp/smtp_enum
​
[msf](Jobs:0 Agents:0) >> use 0
[msf](Jobs:0 Agents:0) auxiliary(scanner/smtp/smtp_enum) >> show options
​
Module options (auxiliary/scanner/smtp/smtp_enum):
​
   Name       Current Setting                               Required  Description
   ----       ---------------                               --------  -----------
   RHOSTS                                                   yes       The target host(s), see https://github.com/rapid7/metasploit-framework/wiki/Usin
                                                                      g-Metasploit
   RPORT      25                                            yes       The target port (TCP)
   THREADS    1                                             yes       The number of concurrent threads (max one per host)
   UNIXONLY   true                                          yes       Skip Microsoft bannered servers when testing unix users
   USER_FILE  /usr/share/metasploit-framework/data/wordlis  yes       The file that contains a list of probable users accounts.
              ts/unix_users.txt
​
[msf](Jobs:0 Agents:0) auxiliary(scanner/smtp/smtp_enum) >> set RHOSTS 10.129.74.23
RHOSTS => 10.129.74.23
[msf](Jobs:0 Agents:0) auxiliary(scanner/smtp/smtp_enum) >> set THREADS 90
THREADS => 90
[msf](Jobs:0 Agents:0) auxiliary(scanner/smtp/smtp_enum) >> set U
set UNIXONLY   set USER_FILE  
[msf](Jobs:0 Agents:0) auxiliary(scanner/smtp/smtp_enum) >> set USER_FILE footprinting-wordlist.txt
USER_FILE => footprinting-wordlist.txt
[msf](Jobs:0 Agents:0) auxiliary(scanner/smtp/smtp_enum) >> show options
​
Module options (auxiliary/scanner/smtp/smtp_enum):
​
   Name       Current Setting            Required  Description
   ----       ---------------            --------  -----------
   RHOSTS     10.129.74.23               yes       The target host(s), see https://github.com/rapid7/metasploit-framework/wiki/Using-Metasploit
   RPORT      25                         yes       The target port (TCP)
   THREADS    90                         yes       The number of concurrent threads (max one per host)
   UNIXONLY   true                       yes       Skip Microsoft bannered servers when testing unix users
   USER_FILE  footprinting-wordlist.txt  yes       The file that contains a list of probable users accounts.
​
[msf](Jobs:0 Agents:0) auxiliary(scanner/smtp/smtp_enum) >> ls -la
[*] exec: ls -la
​
total 64
drwxr-xr-x 1 htb-ac449951 htb-ac449951   480 Nov 30 23:09 .
drwxr-xr-x 1 root         root            24 Nov 30 22:08 ..
-rw-r--r-- 1 htb-ac449951 htb-ac449951  4657 Nov 30 22:08 .bashrc
drwxr-xr-x 1 htb-ac449951 htb-ac449951    48 Nov 30 22:08 .BurpSuite
drwxr-xr-x 1 htb-ac449951 htb-ac449951   268 Nov 30 22:21 .cache
-rw-r--r-- 1 htb-ac449951 htb-ac449951     0 Nov 30 22:08 .cloud-locale-test.skip
drwxr-xr-x 1 htb-ac449951 htb-ac449951  1138 Nov 30 22:08 .config
drwxr-xr-x 1 htb-ac449951 htb-ac449951    18 Nov 30 22:08 .dbeaver4
drwx------ 1 htb-ac449951 htb-ac449951    22 Nov 30 22:08 .dbus
drwxr-xr-x 1 htb-ac449951 htb-ac449951    96 Nov 30 22:09 Desktop
-rwxr-xr-x 1 htb-ac449951 htb-ac449951   482 Nov 30 22:08 .emacs
-rw-r--r-- 1 htb-ac449951 htb-ac449951   719 Dec 13  2021 footprinting-wordlist.txt
-rw-r--r-- 1 htb-ac449951 htb-ac449951   602 Nov 30 23:09 Footprinting-wordlist.zip
-rwxr-xr-x 1 htb-ac449951 htb-ac449951   535 Nov 30 22:08 .gtkrc-2.0
-rw------- 1 htb-ac449951 htb-ac449951   350 Nov 30 22:08 .ICEauthority
drwxr-xr-x 1 htb-ac449951 htb-ac449951    10 Nov 30 22:08 .kde
drwxr-xr-x 1 htb-ac449951 htb-ac449951    16 Nov 30 22:08 .local
drwx------ 1 htb-ac449951 htb-ac449951    72 Nov 30 22:08 .mozilla
drwxr-xr-x 1 htb-ac449951 htb-ac449951    94 Nov 30 23:09 .msf4
-rwxr-xr-x 1 htb-ac449951 htb-ac449951   675 Nov 30 22:08 .profile
drwx------ 1 htb-ac449951 htb-ac449951    22 Nov 30 22:32 .ssh
drwxr-xr-x 1 htb-ac449951 htb-ac449951    22 Nov 30 22:08 Templates
-rwxr-xr-x 1 htb-ac449951 htb-ac449951    74 Nov 30 22:08 .vimrc
drwxr-xr-x 1 htb-ac449951 htb-ac449951   160 Nov 30 22:08 .vnc
-rw------- 1 htb-ac449951 htb-ac449951   108 Nov 30 22:08 .Xauthority
-rw------- 1 htb-ac449951 htb-ac449951 20203 Nov 30 23:11 .xsession-errors
-rwxr-xr-x 1 htb-ac449951 htb-ac449951  2152 Nov 30 22:08 .zshrc
[msf](Jobs:0 Agents:0) auxiliary(scanner/smtp/smtp_enum) >> set USER_FILE footprinting-wordlist.txt
USER_FILE => footprinting-wordlist.txt
​
[msf](Jobs:0 Agents:0) auxiliary(scanner/smtp/smtp_enum) >> exploit
​
[*] 10.129.74.23:25       - 10.129.74.23:25 Banner: 220 InFreight ESMTP v2.11
[+] 10.129.74.23:25       - 10.129.74.23:25 Users found: robin
[*] 10.129.74.23:25       - Scanned 1 of 1 hosts (100% complete)
[*] Auxiliary module execution completed
```
