# Requires: RSAT ActiveDirectory
Import-Module ActiveDirectory -ErrorAction Stop

$krbtgt = Get-ADUser -Filter {SamAccountName -eq 'krbtgt'} -Properties passwordlastset
$days = ((Get-Date) - $krbtgt.PasswordLastSet).TotalDays
@{ KRBTGT_PasswordAgeDays = [int]$days; PasswordLastSet = ($krbtgt.PasswordLastSet).ToString('o') } | ConvertTo-Json -Compress
