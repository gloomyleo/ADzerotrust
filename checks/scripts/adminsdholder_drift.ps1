# Requires: RSAT ActiveDirectory
Import-Module ActiveDirectory -ErrorAction Stop

$domain = Get-ADDomain
$adminSD = Get-ADObject -Identity ("CN=AdminSDHolder,CN=System," + $domain.DistinguishedName) -Properties nTSecurityDescriptor
@{ AdminSDHolderPresent = $true; Recommendation = 'Review AdminSDHolder ACLs for drift; compare to baseline' } | ConvertTo-Json -Compress
