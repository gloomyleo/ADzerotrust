# Requires -Version 5.1
Describe "Collector scripts emit JSON" {
    $scripts = Get-ChildItem -Path "$PSScriptRoot/../../checks/scripts" -Filter *.ps1
    foreach ($s in $scripts) {
        It "Outputs valid JSON: $($s.Name)" {
            $out = & pwsh -NoProfile -NonInteractive -Command "& '$($s.FullName)'" 2>$null
            { $null = $out | ConvertFrom-Json } | Should -Not -Throw
        }
    }
}
