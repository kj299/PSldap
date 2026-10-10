<#
.SYNOPSIS
    Live tests: run psldap.ps1 against a real LDAP server.

.DESCRIPTION
    The unit suite (psldap.Tests.ps1) can't construct SearchResponse /
    SearchResultEntry objects, so it never exercises a real search. Two bugs
    that broke EVERY real search shipped that way (stdout output swallowed,
    and an invalid DereferenceAlias enum name). This tier closes that gap.

    Start the fixture server first:
        tests/live/start-openldap.sh <work-dir> [port]
    then:
        pwsh tests/live/psldap.Live.Tests.ps1 [-Port 3389]

    Exits 0 when every test passes, 1 otherwise.
#>
param(
    [string]$HostName = '127.0.0.1',
    [int]$Port = 3389
)

$ErrorActionPreference = 'Continue'
$script:Passed = 0
$script:Failed = 0
$psldap = Join-Path $PSScriptRoot '..' '..' 'psldap.ps1'
$work = Join-Path ([System.IO.Path]::GetTempPath()) "psldap-live-$PID"
New-Item -ItemType Directory -Path $work -Force | Out-Null

function New-PasswordFile([string]$Name, [string]$Value) {
    $path = Join-Path $work $Name
    [System.IO.File]::WriteAllText($path, $Value)
    return $path
}
$adminPw = New-PasswordFile 'admin.pw' 'password'
$wrongPw = New-PasswordFile 'wrong.pw' 'not-the-password'

# Runs psldap.ps1 in-process (so array parameters bind as arrays) and
# captures every stream, including Write-Host, plus the exit code.
function Invoke-Psldap {
    param(
        [hashtable]$Params,
        [string]$BindDN = 'cn=admin,dc=example,dc=com',
        [string]$PasswordFile = $adminPw
    )
    $base = @{
        hostname = $HostName; port = $Port; baseDN = 'dc=example,dc=com'
        bindDN = $BindDN; bindPasswordFile = $PasswordFile
    }
    $global:LASTEXITCODE = 0
    $output = & $psldap @base @Params *>&1 | Out-String
    return @{ Output = $output; ExitCode = $LASTEXITCODE }
}

function Test-Live {
    param([string]$Name, [scriptblock]$Body)
    try {
        & $Body
        $script:Passed++
        Write-Host "  [PASS] $Name" -ForegroundColor Green
    }
    catch {
        $script:Failed++
        Write-Host "  [FAIL] $Name" -ForegroundColor Red
        Write-Host "         $($_.Exception.Message)" -ForegroundColor DarkRed
    }
}

function Assert-That([bool]$Condition, [string]$Message) {
    if (-not $Condition) { throw $Message }
}

function Get-DnLines([string]$Text) {
    @($Text -split "`r?`n" | Where-Object { $_ -match '^uid=' })
}

Write-Host "`nLive tests against ldap://${HostName}:$Port" -ForegroundColor Cyan

Test-Live 'Default LDIF to stdout, exit 0' {
    $r = Invoke-Psldap @{ filter = '(uid=einstein)' }
    Assert-That ($r.ExitCode -eq 0) "exit $($r.ExitCode): $($r.Output)"
    Assert-That ($r.Output -match 'dn: uid=einstein,dc=example,dc=com') "entry missing: $($r.Output)"
    Assert-That ($r.Output -match 'cn: Albert Einstein') "attribute missing: $($r.Output)"
}

Test-Live 'Attribute names keep server casing (givenName, not givenname)' {
    $r = Invoke-Psldap @{ filter = '(uid=einstein)'; requestedAttribute = @('givenName'); outputFormat = 'JSON' }
    $json = $r.Output.Substring($r.Output.IndexOf('['))
    $json = $json.Substring(0, $json.LastIndexOf(']') + 1)
    $obj = @($json | ConvertFrom-Json)[0]
    Assert-That ($obj.PSObject.Properties.Name -ccontains 'givenName') "keys: $($obj.PSObject.Properties.Name -join ',')"
    Assert-That ($obj.givenName -eq 'Albert') "value: $($obj.givenName)"
}

Test-Live 'Attributes come out in a stable (sorted) order' {
    # .NET randomizes string hashing per PROCESS, so comparing two runs in
    # this one process would prove nothing; assert the order itself instead.
    $r = Invoke-Psldap @{ filter = '(uid=bohr)' }
    $names = @($r.Output -split "`r?`n" | Where-Object { $_ -match '^[A-Za-z][\w-]*::? ' -and $_ -notmatch '^(dn|version):' } |
        ForEach-Object { ($_ -split ':', 2)[0] } | Select-Object -Unique)
    $sorted = @($names | Sort-Object { $_.ToLowerInvariant() })
    Assert-That ($names.Count -ge 5) "too few attributes parsed: $($names -join ',')"
    Assert-That (($names -join ',') -ceq ($sorted -join ',')) "order: $($names -join ',')"
}

Test-Live "Every -dereferencePolicy value works (enum mapping)" {
    foreach ($policy in 'never', 'always', 'search', 'find') {
        $r = Invoke-Psldap @{ filter = '(uid=einstein)'; dereferencePolicy = $policy; outputFormat = 'dns-only' }
        Assert-That ($r.ExitCode -eq 0) "policy '$policy' exit $($r.ExitCode): $($r.Output)"
    }
}

Test-Live "CSV with '*' expands to real columns" {
    $r = Invoke-Psldap @{ filter = '(uid=einstein)'; requestedAttribute = @('*'); outputFormat = 'CSV' }
    $header = @($r.Output -split "`r?`n" | Where-Object { $_ -match ',' })[0]
    Assert-That ($header -match '\bmail\b' -and $header -match '\bgivenName\b') "header: $header"
    Assert-That ($header -notmatch '^\*$|,\*,|^\*,|,\*$') "literal * column: $header"
}

Test-Live 'Multi-valued and non-ASCII values in multi-valued CSV' {
    $r = Invoke-Psldap @{ filter = '(uid=bohr)'; requestedAttribute = @('mail', 'description'); outputFormat = 'multi-valued-csv' }
    Assert-That ($r.Output -match 'bohr@ldap\.example\.com\|niels@ldap\.example\.com') "mail: $($r.Output)"
    Assert-That ($r.Output -match "Årsted Ørsted") "description: $($r.Output)"
}

Test-Live '-countEntries sets the exit code to the match count' {
    $r = Invoke-Psldap @{ filter = '(objectClass=inetOrgPerson)'; countEntries = $true; outputFormat = 'dns-only' }
    Assert-That ($r.ExitCode -eq 7) "exit $($r.ExitCode)"
}

Test-Live 'Paging (-simplePageSize 2) returns every entry' {
    $r = Invoke-Psldap @{ filter = '(objectClass=inetOrgPerson)'; simplePageSize = 2; outputFormat = 'dns-only' }
    Assert-That ($r.ExitCode -eq 0) "exit $($r.ExitCode)"
    Assert-That ((Get-DnLines $r.Output).Count -eq 7) "got $((Get-DnLines $r.Output).Count): $($r.Output)"
}

Test-Live '-sizeLimit writes partial results and still exits 4' {
    $r = Invoke-Psldap @{ filter = '(objectClass=inetOrgPerson)'; sizeLimit = 3; outputFormat = 'dns-only' }
    Assert-That ($r.ExitCode -eq 4) "exit $($r.ExitCode)"
    Assert-That ((Get-DnLines $r.Output).Count -eq 3) "got $((Get-DnLines $r.Output).Count): $($r.Output)"
}

Test-Live 'Server-enforced size limit writes partial results and exits 4' {
    $r = Invoke-Psldap @{ filter = '(objectClass=inetOrgPerson)'; outputFormat = 'dns-only' } -BindDN 'cn=read-only-admin,dc=example,dc=com'
    Assert-That ($r.ExitCode -eq 4) "exit $($r.ExitCode)"
    Assert-That ((Get-DnLines $r.Output).Count -eq 5) "got $((Get-DnLines $r.Output).Count): $($r.Output)"
}

Test-Live '-typesOnly LDIF lists attribute names without values' {
    $r = Invoke-Psldap @{ filter = '(uid=einstein)'; typesOnly = $true }
    Assert-That ($r.ExitCode -eq 0) "exit $($r.ExitCode)"
    Assert-That ($r.Output -match '(?m)^givenName:\s*$') "no bare 'givenName:' line: $($r.Output)"
    Assert-That ($r.Output -notmatch 'Albert') "values leaked: $($r.Output)"
}

Test-Live 'Server-side sort (-sortOrder) orders results' {
    $r = Invoke-Psldap @{ filter = '(objectClass=inetOrgPerson)'; sortOrder = '-sn:caseIgnoreOrderingMatch'; outputFormat = 'dns-only' }
    Assert-That ($r.ExitCode -eq 0) "exit $($r.ExitCode): $($r.Output)"
    $dns = Get-DnLines $r.Output
    Assert-That ($dns[0] -match 'uid=tesla' -and $dns[-1] -match 'uid=bohr') "order: $($dns -join ' ; ')"
}

Test-Live 'Redaction applies to real entries' {
    $r = Invoke-Psldap @{ filter = '(uid=bohr)'; requestedAttribute = @('mail'); redactAttribute = @('mail'); outputFormat = 'JSON' }
    Assert-That ($r.Output -match 'REDACTED1' -and $r.Output -match 'REDACTED2') "output: $($r.Output)"
    Assert-That ($r.Output -notmatch 'niels@') "value leaked: $($r.Output)"
}

Test-Live 'Two searches share one LDIF -outputFile' {
    $filters = Join-Path $work 'two.txt'
    Set-Content -Path $filters -Value @('(uid=einstein)', '(uid=newton)')
    $out = Join-Path $work 'shared.ldif'
    $r = Invoke-Psldap @{ filterFile = $filters; outputFile = $out; requestedAttribute = @('cn') }
    Assert-That ($r.ExitCode -eq 0) "exit $($r.ExitCode): $($r.Output)"
    $content = Get-Content -Path $out -Raw
    Assert-That ($content -match 'uid=einstein' -and $content -match 'uid=newton') "content: $content"
    Assert-That ([regex]::Matches($content, 'version: 1').Count -eq 1) "header count: $content"
}

Test-Live 'Wrong password exits 49 (invalidCredentials)' {
    $r = Invoke-Psldap @{ filter = '(uid=einstein)' } -PasswordFile $wrongPw
    Assert-That ($r.ExitCode -eq 49) "exit $($r.ExitCode): $($r.Output)"
}

Test-Live '-requireMatch exits 1 when nothing matches' {
    $r = Invoke-Psldap @{ filter = '(uid=nobody)'; requireMatch = $true; outputFormat = 'dns-only' }
    Assert-That ($r.ExitCode -eq 1) "exit $($r.ExitCode)"
}

Remove-Item -Path $work -Recurse -Force -ErrorAction SilentlyContinue

Write-Host "`n  Passed: $script:Passed   Failed: $script:Failed" -ForegroundColor $(if ($script:Failed) { 'Red' } else { 'Green' })
if ($script:Failed -gt 0) { exit 1 }
exit 0
