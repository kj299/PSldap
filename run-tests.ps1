<#
.SYNOPSIS
    Runs the unit tests for psldap.ps1.
    No external modules required — uses built-in test harness.
.EXAMPLE
    .\run-tests.ps1
    .\run-tests.ps1 -Iterations 3
#>
param(
    [int]$Iterations = 3
)

for ($i = 1; $i -le $Iterations; $i++) {
    Write-Host "`n============================================" -ForegroundColor Cyan
    Write-Host "  Test Run $i of $Iterations" -ForegroundColor Cyan
    Write-Host "============================================" -ForegroundColor Cyan

    # Dot-source so harness functions remain visible in this scope
    . (Join-Path $PSScriptRoot 'psldap.Tests.ps1')

    $summary = Get-TestSummary
    $total = $summary.Passed + $summary.Failed

    Write-Host "`n--- Run $i Summary ---" -ForegroundColor Yellow
    Write-Host "  Passed : $($summary.Passed)" -ForegroundColor Green
    Write-Host "  Failed : $($summary.Failed)" -ForegroundColor $(if ($summary.Failed -gt 0) { 'Red' } else { 'Green' })
    Write-Host "  Total  : $total" -ForegroundColor White

    if ($summary.Errors.Count -gt 0) {
        Write-Host "`n  Failures:" -ForegroundColor Red
        foreach ($err in $summary.Errors) {
            Write-Host "    $err" -ForegroundColor Red
        }
    }

    Reset-TestResults
}
