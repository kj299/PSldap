<#
.SYNOPSIS
    Lightweight, native-only test harness for Invoke-AdLdapQuery.ps1.

.DESCRIPTION
    Two test categories with explicit gating:

    1. Offline tests — always run. No AD connectivity required. Cover
       script load, function existence, and parameter validation that
       the function performs locally before any LDAP I/O.

    2. Live AD tests — gated behind RUN_LIVE_AD_TESTS=1. Run only on a
       domain-joined machine (or a self-hosted CI runner). Issue safe,
       read-only LDAP queries against the current user's domain.

    Default behaviour (env var unset): only offline tests run. The
    harness can therefore execute unmodified on a stock GitHub-hosted
    windows-latest runner — CI passes on offline correctness, AD
    connectivity is not required.

    On a domain-joined machine, set RUN_LIVE_AD_TESTS=1 to run the full
    suite. If the env var is set but the machine cannot reach AD, the
    live tests fail loudly (this is operator misconfiguration, not a
    routine condition).

.PARAMETER Json
    Emit machine-readable JSON to stdout instead of the default
    formatted table. Useful for piping into a result aggregator.

.PARAMETER Detailed
    Verbose per-test logging (entry, retry attempts, timings).

.EXAMPLE
    # Stock CI (offline only)
    .\Test-AdLdapQueryHarness.ps1

.EXAMPLE
    # Full run on a domain-joined workstation
    $env:RUN_LIVE_AD_TESTS = '1'
    .\Test-AdLdapQueryHarness.ps1

.EXAMPLE
    # JSON output for downstream tooling
    .\Test-AdLdapQueryHarness.ps1 -Json | Out-File results.json -Encoding utf8

.NOTES
    PS 5.x compatible. No CmdletBinding, no Pester, no external
    modules. Exit code 0 = all pass (or skip), 1 = at least one FAIL.

    Optional env vars:
      RUN_LIVE_AD_TESTS    '1' to enable live AD tests (default: off)
      LIVE_AD_TEST_RETRIES integer N → up to N retries on transient
                           LDAP failures (default: 0, no retries)
#>

param(
    [switch]$Json,
    [switch]$Detailed
)

$ErrorActionPreference = 'Stop'

# ============================================================================
# Result collector
# ============================================================================
$script:Results = New-Object System.Collections.Generic.List[object]

function Add-Result {
    param(
        [string]$Name,
        [ValidateSet('PASS','FAIL','SKIP')]
        [string]$Status,
        [string]$Message = '',
        [int]$DurationMs = 0
    )
    $row = [PSCustomObject]@{
        Test     = $Name
        Status   = $Status
        Duration = $DurationMs
        Message  = $Message
    }
    $script:Results.Add($row)
    if (-not $Json -and $Detailed) {
        $color = switch ($Status) { 'PASS' { 'Green' }; 'FAIL' { 'Red' }; default { 'Yellow' } }
        Write-Host ("    [{0,-4}] {1} ({2} ms) {3}" -f $Status, $Name, $DurationMs, $Message) -ForegroundColor $color
    }
}

# ============================================================================
# Pre-flight environment detection
# ============================================================================
$script:LiveAdEnabled        = ($env:RUN_LIVE_AD_TESTS -eq '1')
$script:DomainAvailable      = $false
$script:DomainName           = $null
$script:DomainDiscoveryError = $null

try {
    $d = [System.DirectoryServices.ActiveDirectory.Domain]::GetCurrentDomain()
    $script:DomainAvailable = $true
    $script:DomainName = $d.Name
}
catch {
    $script:DomainDiscoveryError = $_.Exception.Message
}

# ============================================================================
# Test wrappers
# ============================================================================
function Run-OfflineTest {
    <#
    .SYNOPSIS
        Run a test that does not require AD. Always executes.
    #>
    param(
        [string]$Name,
        [scriptblock]$Body
    )
    $sw = [System.Diagnostics.Stopwatch]::StartNew()
    try {
        & $Body
        $sw.Stop()
        Add-Result -Name $Name -Status 'PASS' -DurationMs ([int]$sw.ElapsedMilliseconds)
    }
    catch {
        $sw.Stop()
        Add-Result -Name $Name -Status 'FAIL' -DurationMs ([int]$sw.ElapsedMilliseconds) `
            -Message ("Exception: " + $_.Exception.Message)
    }
}

function Run-LiveTest {
    <#
    .SYNOPSIS
        Run a test that requires AD. Behaviour:
          - RUN_LIVE_AD_TESTS != 1                : SKIP
          - RUN_LIVE_AD_TESTS = 1, AD unreachable : FAIL (misconfig)
          - RUN_LIVE_AD_TESTS = 1, AD reachable   : execute (with retries
                                                    if LIVE_AD_TEST_RETRIES set)
    #>
    param(
        [string]$Name,
        [scriptblock]$Body
    )
    if (-not $script:LiveAdEnabled) {
        Add-Result -Name $Name -Status 'SKIP' `
            -Message 'Live AD tests disabled (set RUN_LIVE_AD_TESTS=1 to enable)'
        return
    }
    if (-not $script:DomainAvailable) {
        Add-Result -Name $Name -Status 'FAIL' `
            -Message ("RUN_LIVE_AD_TESTS=1 but AD is unreachable: " + $script:DomainDiscoveryError)
        return
    }

    # Retry budget for transient failures
    $maxAttempts = 1
    if ($env:LIVE_AD_TEST_RETRIES) {
        $parsed = 0
        if ([int]::TryParse($env:LIVE_AD_TEST_RETRIES, [ref]$parsed)) {
            $maxAttempts = [Math]::Max(1, $parsed + 1)
        }
    }

    $sw = [System.Diagnostics.Stopwatch]::StartNew()
    $attempt = 0
    while ($true) {
        $attempt++
        try {
            & $Body
            $sw.Stop()
            $msg = if ($attempt -gt 1) { "Succeeded on attempt $attempt" } else { '' }
            Add-Result -Name $Name -Status 'PASS' -DurationMs ([int]$sw.ElapsedMilliseconds) -Message $msg
            return
        }
        catch {
            $msg = $_.Exception.Message
            $isTransient = $msg -match 'server is not operational|server unavailable|0x80072030|connection.*reset|timed?\s*out|RPC server is unavailable'
            if ($isTransient -and $attempt -lt $maxAttempts) {
                if ($Detailed) {
                    Write-Host ("    [retry] {0} attempt {1}: {2}" -f $Name, $attempt, $msg) -ForegroundColor DarkYellow
                }
                Start-Sleep -Seconds 2
                continue
            }
            $sw.Stop()
            Add-Result -Name $Name -Status 'FAIL' -DurationMs ([int]$sw.ElapsedMilliseconds) `
                -Message ("Exception: " + $msg)
            return
        }
    }
}

function Assert-True {
    param($Value, [string]$Message = '')
    if (-not $Value) { throw "Expected truthy. $Message" }
}

function Assert-Equal {
    param($Expected, $Actual, [string]$Message = '')
    if ($Expected -ne $Actual) {
        throw ("Expected '{0}', got '{1}'. {2}" -f $Expected, $Actual, $Message)
    }
}

# ============================================================================
# Pre-flight (informational)
# ============================================================================
$preflightStatus  = if ($script:DomainAvailable) { 'PASS' } else { 'SKIP' }
$preflightMessage = if ($script:DomainAvailable) { $script:DomainName } `
                    else { "Not reachable: $($script:DomainDiscoveryError)" }
Add-Result -Name 'AD domain discovery (pre-flight)' -Status $preflightStatus -Message $preflightMessage

# ============================================================================
# Offline tests
# ============================================================================
$scriptPath = Join-Path $PSScriptRoot 'Invoke-AdLdapQuery.ps1'

Run-OfflineTest 'Script file exists' {
    Assert-True (Test-Path $scriptPath -PathType Leaf) "Expected $scriptPath"
}

Run-OfflineTest 'Native DirectoryServices types are loadable' {
    [void][System.DirectoryServices.DirectoryEntry]
    [void][System.DirectoryServices.DirectorySearcher]
    [void][System.DirectoryServices.ActiveDirectory.Domain]
}

# Dot-source once in the harness scope so subsequent tests can call the
# function directly. If dot-source fails, the per-test "function exists"
# check below will fail with a clear message.
$dotSourceOk = $false
$dotSourceErr = $null
try {
    . $scriptPath
    $dotSourceOk = $true
}
catch {
    $dotSourceErr = $_.Exception.Message
}

Run-OfflineTest 'Script dot-sources cleanly' {
    Assert-True $dotSourceOk "Dot-source failed: $dotSourceErr"
}

Run-OfflineTest 'Function Invoke-AdLdapQuery is defined after dot-source' {
    $cmd = Get-Command Invoke-AdLdapQuery -ErrorAction SilentlyContinue
    Assert-True ($null -ne $cmd) "Invoke-AdLdapQuery not defined"
}

Run-OfflineTest 'Empty filter is rejected' {
    $threw = $false
    try { Invoke-AdLdapQuery -Filter '' } catch { $threw = $true }
    Assert-True $threw "Empty filter should throw before any AD I/O"
}

Run-OfflineTest 'Whitespace-only filter is rejected' {
    $threw = $false
    try { Invoke-AdLdapQuery -Filter '   ' } catch { $threw = $true }
    Assert-True $threw "Whitespace-only filter should throw"
}

Run-OfflineTest 'Malformed filter (unbalanced parens) is rejected before AD I/O' {
    $threw = $false
    $errMsg = ''
    try { Invoke-AdLdapQuery -Filter '(objectClass=user' } catch { $threw = $true; $errMsg = $_.Exception.Message }
    Assert-True $threw "Unbalanced filter should throw locally"
    # The error must mention the local validation, not an LDAP server error,
    # so we know we did not attempt a round-trip.
    Assert-True ($errMsg -match 'Invalid LDAP filter') "Expected local validation message, got: $errMsg"
}

Run-OfflineTest 'Negative MaxResults is rejected' {
    $threw = $false
    try { Invoke-AdLdapQuery -Filter '(objectClass=user)' -MaxResults -1 } catch { $threw = $true }
    Assert-True $threw "Negative MaxResults should throw"
}

# ============================================================================
# Live AD tests (gated)
# ============================================================================
Run-LiveTest 'Basic user query returns at least one result' {
    $r = @(Invoke-AdLdapQuery -Filter '(objectClass=user)' -MaxResults 5)
    Assert-True ($r.Count -gt 0) "Expected >= 1 result, got $($r.Count)"
}

Run-LiveTest 'Selected properties returns only the requested attributes' {
    $r = @(Invoke-AdLdapQuery -Filter '(objectClass=user)' -Properties @('samAccountName') -MaxResults 1)
    Assert-True ($r.Count -ge 1) "Expected >= 1 result"
    $first = $r[0]
    $names = @($first.PSObject.Properties.Name)
    Assert-Equal 1 $names.Count "Expected 1 property, got $($names.Count): $($names -join ',')"
    Assert-Equal 'samAccountName' $names[0] "Property name should be samAccountName"
}

Run-LiveTest 'No-results query returns an empty set without throwing' {
    $needle = '__definitely_does_not_exist_q9z__'
    $r = @(Invoke-AdLdapQuery -Filter "(samAccountName=$needle)" -MaxResults 5)
    Assert-Equal 0 $r.Count "Expected 0 results for nonexistent samAccountName"
}

Run-LiveTest 'Returned objects expose distinguishedName' {
    $r = @(Invoke-AdLdapQuery -Filter '(objectClass=user)' -Properties @('distinguishedName') -MaxResults 1)
    Assert-True ($r.Count -ge 1) "Expected >= 1 result"
    Assert-True (-not [string]::IsNullOrWhiteSpace($r[0].distinguishedName)) "distinguishedName should be populated"
}

# ============================================================================
# Output
# ============================================================================
# Use List<T>.ToArray() rather than @($list). The @() array-subexpression
# operator on a [System.Collections.Generic.List[object]] throws
# `ArgumentException: Argument types do not match` on both PowerShell 7
# and Windows PowerShell 5.1 (under $ErrorActionPreference = 'Stop' it
# becomes terminating). .ToArray() is unambiguous on both shells.
$resultsArr = $script:Results.ToArray()
$passed  = @($resultsArr | Where-Object { $_.Status -eq 'PASS' }).Count
$failed  = @($resultsArr | Where-Object { $_.Status -eq 'FAIL' }).Count
$skipped = @($resultsArr | Where-Object { $_.Status -eq 'SKIP' }).Count

if ($Json) {
    [PSCustomObject]@{
        domain        = $script:DomainName
        liveTestsMode = if ($script:LiveAdEnabled) { 'enabled' } else { 'disabled' }
        passed        = $passed
        failed        = $failed
        skipped       = $skipped
        results       = $resultsArr
    } | ConvertTo-Json -Depth 5
}
else {
    $displayDomain = if ($script:DomainName) { $script:DomainName } else { '<none>' }
    $displayLive   = if ($script:LiveAdEnabled) { 'ENABLED' } else { 'disabled (set RUN_LIVE_AD_TESTS=1)' }
    Write-Host ""
    Write-Host "Domain        : $displayDomain"
    Write-Host "Live AD tests : $displayLive"
    Write-Host ""
    $resultsArr | Format-Table -AutoSize Test, Status, Duration, Message | Out-String | Write-Host
    Write-Host ("Passed: {0}   Failed: {1}   Skipped: {2}" -f $passed, $failed, $skipped)
}

if ($failed -gt 0) { exit 1 } else { exit 0 }
