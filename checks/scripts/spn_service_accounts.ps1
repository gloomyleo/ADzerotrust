# Requires: RSAT ActiveDirectory
Import-Module ActiveDirectory -ErrorAction Stop

$svc = Get-ADUser -LDAPFilter '(servicePrincipalName=*)' -Properties servicePrincipalName,PasswordLastSet,UserAccountControl | 
    Select-Object SamAccountName, PasswordLastSet, servicePrincipalName, UserAccountControl
@{ ServiceAccounts = ($svc | Select-Object -First 20); Total = $svc.Count } | ConvertTo-Json -Compress
