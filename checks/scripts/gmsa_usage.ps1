# Requires: RSAT ActiveDirectory
Import-Module ActiveDirectory -ErrorAction Stop

$gmsa = Get-ADServiceAccount -Filter * -Properties PrincipalsAllowedToRetrieveManagedPassword
@{ gMSACount = $gmsa.Count; Examples = ($gmsa | Select-Object -First 20 -ExpandProperty Name) } | ConvertTo-Json -Compress
