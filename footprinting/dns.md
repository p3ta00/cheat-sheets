# Dig
## Enumerate FQDN
```
dig ns inlanefreight.htb @10.129.42.195
```
## Zone Transfer
```
dig axfr internal.inlanefreight.htb @10.129.42.195
```

# DNS Enum
```
dnsenum --dnsserver 10.129.42.195 --enum -p 0 -s 0 -o subdomains.txt -f /usr/share/wordlists/seclists/Discovery/DNS/fierce-hostlist.txt dev.inlanefreight.htb --threads 90
```
