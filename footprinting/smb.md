# SMBClient
```
nmap -sCV -Pn -T4 -p 139 10.129.202.5
```

```
smbclient -N -L 10.129.202.5
```

```
smbclient \\\\10.129.202.5\\sambashare
```
# Enum4linux
```
enum4linux 10.129.202.5 -A
```
# RPC Client
```
rpcclient -U "" <FQDN/IP>
```
```
rpcclient $> netsharegetinfo sambashare
```
# Impacket
```
samrdump.py <FQDN/IP>
```
# SMB Map
```
smbmap -H <FQDN/IP>
```
# CME
```
crackmapexec smb <FQDN/IP> --shares -u '' -p ''
```

