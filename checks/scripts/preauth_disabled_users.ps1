# Requires: RSAT ActiveDirectory
Import-Module ActiveDirectory -ErrorAction Stop

$users = Get-ADUser -LDAPFilter '(userAccountControl:1.2.840.113556.1.4.803:=4194304)' -Properties SamAccountName
@{ PreAuthDisabledCount = $users.Count; Examples = ($users | Select-Object -First 10 -ExpandProperty SamAccountName) } | ConvertTo-Json -Compress
