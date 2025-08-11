# Requires: RSAT ActiveDirectory
Import-Module ActiveDirectory -ErrorAction Stop

$unconstrained = Get-ADComputer -LDAPFilter '(userAccountControl:1.2.840.113556.1.4.803:=524288)' -Properties dNSHostName | Select-Object -ExpandProperty dNSHostName
$constrained = Get-ADUser -Filter * -Properties msDS-AllowedToDelegateTo | Where-Object {$_. 'msDS-AllowedToDelegateTo'} | Select-Object SamAccountName, 'msDS-AllowedToDelegateTo'
$rbcd = Get-ADObject -LDAPFilter '(msDS-AllowedToActOnBehalfOfOtherIdentity=*)' -SearchBase (Get-ADDomain).DistinguishedName -SearchScope Subtree -Properties *
@{ UnconstrainedDelegationHosts = $unconstrained; ConstrainedDelegationPrincipals = $constrained | Select-Object -First 20; RBCDObjects = ($rbcd | Select-Object -First 20 -ExpandProperty DistinguishedName) } | ConvertTo-Json -Compress
