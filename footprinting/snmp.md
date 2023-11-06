# NMAP
```
sudo nmap --script=nfs-ls -Pn  10.129.202.5 -sV -p111,2049
```
# Mounting
```
sudo mount -t nfs 10.129.202.5:/ ./target-NFS/ -o nolock
```
# SNMPwalk
```
snmpwalk -v2c -c <community string> <FQDN/IP>
```
### Examples
```
snmpwalk -v 2c -c public 10.129.74.23
```
```
snmpwalk -v 2c -c private  10.129.42.253
```
# Onesixtyone
```
onesixtyone -c community-strings.list <FQDN/IP>
```
### Examples
```
noob2uub@htb[/htb]$ onesixtyone -c dict.txt 10.129.42.254

Scanning 1 hosts, 51 communities
10.129.42.254 [public] Linux gs-svcscan 5.4.0-66-generic #74-Ubuntu SMP Wed Jan 27 22:54:38 UTC 2021 x86_64
```
https://github.com/trailofbits/onesixtyone
# Bra
```
braa <community string>@<FQDN/IP>:.1.*
```
### Examples
```
noob2uub@htb[/htb]$ sudo apt install braa
noob2uub@htb[/htb]$ braa <community string>@<IP>:.1.3.6.*   # Syntax
noob2uub@htb[/htb]$ braa public@10.129.14.128:.1.3.6.*

10.129.14.128:20ms:.1.3.6.1.2.1.1.1.0:Linux htb 5.11.0-34-generic #36~20.04.1-Ubuntu SMP Fri Aug 27 08:06:32 UTC 2021 x86_64
10.129.14.128:20ms:.1.3.6.1.2.1.1.2.0:.1.3.6.1.4.1.8072.3.2.10
10.129.14.128:20ms:.1.3.6.1.2.1.1.3.0:548
10.129.14.128:20ms:.1.3.6.1.2.1.1.4.0:mrb3n@inlanefreight.htb
10.129.14.128:20ms:.1.3.6.1.2.1.1.5.0:htb
10.129.14.128:20ms:.1.3.6.1.2.1.1.6.0:US
10.129.14.128:20ms:.1.3.6.1.2.1.1.7.0:78
...SNIP...
```
