# NMAP
```
nmap -sCV -A -T4 
```
### NMAP Grep Cheatsheet
https://github.com/leonjza/awesome-nmap-grep

# Banner Grab
```
curl -IL http://10.129.203.114
```
# VHOST Enumeration
## GoBuster
```
gobuster vhost -u inlanefreight.local -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt
```
## FFUF
```
ffuf -w /usr/share/wordlists/seclists/Discovery/DNS/bitquark-subdomains-top100000.txt -u http://10.129.203.114 -H "HOST: FUZZ.inlanefreight.local" -fs 15157
```
Add any VHOST's found to your /etc/hosts file
# FTP
Check anoumyous login
# SSH
```
nc -nv 10.129.203.114 22
```
# Telnet
```
telnet 10.129.203.101 25

Trying 10.129.203.101...
Connected to 10.129.203.101.
Escape character is '^]'.
220 ubuntu ESMTP Postfix (Ubuntu)
VRFY root
252 2.0.0 root
VRFY www-data
252 2.0.0 www-data
VRFY randomuser
550 5.1.1 <randomuser>: Recipient address rejected: User unknown in local recipient table
```

### Open Relay
```
nmap -p25 -Pn --script smtp-open-relay 10.129.203.114
Starting Nmap 7.93 ( https://nmap.org ) at 2023-05-05 10:12 PDT
Nmap scan report for inlanefreight.local (10.129.203.114)
Host is up (0.077s latency).

PORT   STATE SERVICE
25/tcp open  smtp
|_smtp-open-relay: Server doesn't seem to be an open relay, all tests failed

Nmap done: 1 IP address (1 host up) scanned in 28.96 seconds
```
# RPC Info
```
rpcinfo 10.129.203.114
```
https://book.hacktricks.xyz/network-services-pentesting/pentesting-rpcbind

# Eyewitness
Run Eyewitness against all of the subdomains
```
eyewitness -f subdomains.txt -d ILFRIGHT_subdomain_EyeWitness
```


