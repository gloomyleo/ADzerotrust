# Requires: RSAT ActiveDirectory
Import-Module ActiveDirectory -ErrorAction Stop

$computers = Get-ADComputer -Filter * -Properties 'ms-Mcs-AdmPwdExpirationTime','msLAPS-PasswordExpirationTime'
$total = $computers.Count
$legacy = ($computers | Where-Object { $_.'ms-Mcs-AdmPwdExpirationTime' }).Count
$winlaps = ($computers | Where-Object { $_.'msLAPS-PasswordExpirationTime' }).Count
$covered = [int]$legacy + [int]$winlaps
$percent = if ($total -gt 0) { [math]::Round(($covered / $total) * 100,2) } else { 0 }
@{ TotalComputers = $total; LegacyLAPS = $legacy; WindowsLAPS = $winlaps; CoveragePercent = $percent } | ConvertTo-Json -Compress
