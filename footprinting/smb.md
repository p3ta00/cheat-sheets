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

```
enum4linux 10.129.202.5 -A
```
# RPC Client
```
rpcclient $> netsharegetinfo sambashare
```
