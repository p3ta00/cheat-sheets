# Interact with the FTP service on the target.
```
ftp <FQDN/IP>	
```
```
nc -nv <FQDN/IP> 21
```
```
telnet <FQDN/IP> 21
```
# Interact with the FTP service on the target using encrypted connection.
```
openssl s_client -connect <FQDN/IP>:21 -starttls ftp
```
# Download all files from Target
```
wget -m --no-passive ftp://anonymous:anonymous@<target>
```
