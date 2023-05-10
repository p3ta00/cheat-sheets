# Powerview
## Changing Password
verify net use in cmd
```
Import-Module .\PowerView.ps1
```
```
Set-DomainUserPassword -Identity ssmalls -AccountPassword (ConvertTo-SecureString 'password1' -AsPlainText -Force ) -Verbose
```
