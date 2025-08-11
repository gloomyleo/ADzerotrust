
$results = @()
try {
  $rootDN = ([ADSI]'LDAP://RootDSE').configurationNamingContext
  $tmplCN = "CN=Certificate Templates,CN=Public Key Services,CN=Services," + $rootDN
  $searcher = New-Object System.DirectoryServices.DirectorySearcher([ADSI]("LDAP://$tmplCN"))
  $searcher.Filter = '(objectClass=pKICertificateTemplate)'; $searcher.PageSize = 2000
  $searcher.PropertiesToLoad.AddRange(@('cn','msPKI-Enrollment-Flag','msPKI-RA-Requirements','pKIExtendedKeyUsage'))
  $res = $searcher.FindAll()
  foreach ($r in $res) {
    $cn = $r.Properties['cn'][0]
    $enrollFlag = [int]$r.Properties['msPKI-Enrollment-Flag'][0]
    $raReq = $r.Properties['msPKI-RA-Requirements']
    $ekus = $r.Properties['pKIExtendedKeyUsage']
    $enrolleeSupplies = ($enrollFlag -band 0x00000001) -ne 0
    $managerApproval = $false
    if ($raReq -and $raReq.Count -gt 0) {{ $managerApproval = ($raReq[0] -band 0x1) -ne 0 }}
    $clientAuth = $false
    if ($ekus) {{ $clientAuth = ($ekus -contains '1.3.6.1.5.5.7.3.2') }}
    $results += [pscustomobject]@{{ Template=$cn; EnrolleeSuppliesSubject=$enrolleeSupplies; ManagerApproval=$managerApproval; ClientAuthEKU=$clientAuth }}
  }
} catch { }
@{ Templates = $results | Select-Object -First 50 } | ConvertTo-Json -Compress
