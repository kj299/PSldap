<#
.SYNOPSIS
    Unit tests for psldap.ps1 helper functions.
    Uses a built-in lightweight test harness — no external modules required.
    Run with: .\run-tests.ps1 -Iterations 3
#>

# ============================================================================
# Lightweight Test Harness (no external dependencies)
# ============================================================================

$script:TestResults = @{ Passed = 0; Failed = 0; Errors = @() }
$script:CurrentDescribe = ''

function Describe {
    param([string]$Name, [scriptblock]$Body)
    $script:CurrentDescribe = $Name
    Write-Host "`n  $Name" -ForegroundColor Cyan
    & $Body
}

function It {
    param([string]$Name, [scriptblock]$Body)
    try {
        & $Body
        $script:TestResults.Passed++
        Write-Host "    [PASS] $Name" -ForegroundColor Green
    }
    catch {
        $script:TestResults.Failed++
        $errMsg = $_.Exception.Message
        $script:TestResults.Errors += "[FAIL] $($script:CurrentDescribe) > $Name : $errMsg"
        Write-Host "    [FAIL] $Name" -ForegroundColor Red
        Write-Host "           $errMsg" -ForegroundColor DarkRed
    }
}

function Assert-Equal {
    param($Expected, $Actual, [string]$Message)
    if ($Expected -ne $Actual) {
        throw ($Message + " Expected: '$Expected', Got: '$Actual'")
    }
}

function Assert-True {
    param($Value, [string]$Message)
    if (-not $Value) { throw ($Message + " Expected True, Got False") }
}

function Assert-False {
    param($Value, [string]$Message)
    if ($Value) { throw ($Message + " Expected False, Got True") }
}

function Assert-Match {
    param([string]$String, [string]$Pattern, [string]$Message)
    if ($String -notmatch $Pattern) {
        throw ($Message + " '$String' did not match pattern '$Pattern'")
    }
}

function Assert-NotMatch {
    param([string]$String, [string]$Pattern, [string]$Message)
    if ($String -match $Pattern) {
        throw ($Message + " '$String' should not match pattern '$Pattern'")
    }
}

function Assert-Contains {
    param($Collection, $Item, [string]$Message)
    if ($Collection -notcontains $Item) {
        throw ($Message + " Collection does not contain '$Item'")
    }
}

function Assert-NotNull {
    param($Value, [string]$Message)
    if ($null -eq $Value) { throw ($Message + " Expected non-null value") }
}

function Get-TestSummary {
    return $script:TestResults
}

function Reset-TestResults {
    $script:TestResults = @{ Passed = 0; Failed = 0; Errors = @() }
}

# ============================================================================
# Load functions from psldap.ps1
# ============================================================================
# psldap.ps1 short-circuits its Main Execution block when dot-sourced
# ($MyInvocation.InvocationName -eq '.'), so dot-sourcing only loads helpers.
#
# Side effect: dot-sourcing also imports psldap.ps1's param() block as
# variables in this scope (e.g. $hostname, $port, $baseDN, $filter, $scope).
# Avoid those names when introducing new test-scoped variables, or shadow
# them deliberately inside an `It` block.

. (Join-Path $PSScriptRoot 'psldap.ps1')

# ============================================================================
# Test-LdapFilter Tests
# ============================================================================
Describe 'Test-LdapFilter' {
    It 'Returns true for valid simple filter' {
        Assert-True (Test-LdapFilter -Filter '(objectClass=user)')
    }

    It 'Returns true for valid AND filter' {
        Assert-True (Test-LdapFilter -Filter '(&(objectClass=user)(cn=John))')
    }

    It 'Returns true for valid OR filter' {
        Assert-True (Test-LdapFilter -Filter '(|(cn=John)(cn=Jane))')
    }

    It 'Returns true for nested filters' {
        Assert-True (Test-LdapFilter -Filter '(&(objectClass=user)(|(cn=John)(cn=Jane)))')
    }

    It 'Returns false for empty string' {
        Assert-False (Test-LdapFilter -Filter '')
    }

    It 'Returns false for null' {
        Assert-False (Test-LdapFilter -Filter $null)
    }

    It 'Returns false for missing opening paren' {
        Assert-False (Test-LdapFilter -Filter 'objectClass=user)')
    }

    It 'Returns false for missing closing paren' {
        Assert-False (Test-LdapFilter -Filter '(objectClass=user')
    }

    It 'Returns false for unbalanced parens' {
        Assert-False (Test-LdapFilter -Filter '((objectClass=user)')
    }

    It 'Returns true for wildcard filter' {
        Assert-True (Test-LdapFilter -Filter '(objectClass=*)')
    }
}

# ============================================================================
# Get-StableStringHash Tests
# ============================================================================
Describe 'Get-StableStringHash' {
    It 'Returns 0 for empty string' {
        Assert-Equal 0 (Get-StableStringHash -Value '')
    }

    It 'Returns 0 for $null input' {
        Assert-Equal 0 (Get-StableStringHash -Value $null)
    }

    It 'Pins MD5-derived Int32 output for "hello"' {
        # MD5("hello") = 5d41402abc4b2a76b9719d911017c592
        # First 4 bytes -> BitConverter::ToInt32 (little-endian) = 0x2a40415d.
        # Pinning the exact value catches:
        #   1. any change to the hashing algorithm (e.g. revert to GetHashCode)
        #   2. accidental endianness changes
        #   3. UTF-8 vs. UTF-16 encoding regressions
        # Assumes little-endian (true on every platform PowerShell runs on).
        Assert-Equal 0x2a40415d (Get-StableStringHash -Value 'hello')
    }

    It 'Produces the same output across repeated calls in this process' {
        # Within a single process this is also true of GetHashCode(), so this
        # test alone does not catch the cross-process regression — see the
        # Regression Tests block for that. Kept here as a basic sanity check.
        $a = Get-StableStringHash -Value 'TestValue'
        $b = Get-StableStringHash -Value 'TestValue'
        Assert-Equal $a $b
    }
}

# ============================================================================
# Invoke-ScrambleValue Tests
# ============================================================================
Describe 'Invoke-ScrambleValue' {
    It 'Preserves length of input string' {
        $result = Invoke-ScrambleValue -Value 'Hello123' -Seed 42
        Assert-Equal 8 $result.Length
    }

    It 'Preserves special characters unchanged' {
        $result = Invoke-ScrambleValue -Value 'a@b.c' -Seed 42
        Assert-Equal '@' $result[1]
        Assert-Equal '.' $result[3]
    }

    It 'Preserves uppercase character class' {
        $result = Invoke-ScrambleValue -Value 'ABCDEF' -Seed 42
        Assert-Match $result '^[A-Z]{6}$'
    }

    It 'Preserves lowercase character class' {
        $result = Invoke-ScrambleValue -Value 'abcdef' -Seed 42
        Assert-Match $result '^[a-z]{6}$'
    }

    It 'Preserves digit character class' {
        $result = Invoke-ScrambleValue -Value '123456' -Seed 42
        Assert-Match $result '^\d{6}$'
    }

    It 'Produces deterministic output with same seed' {
        $result1 = Invoke-ScrambleValue -Value 'TestValue' -Seed 99
        $result2 = Invoke-ScrambleValue -Value 'TestValue' -Seed 99
        Assert-Equal $result1 $result2
    }

    It 'Produces different output with different seeds' {
        $result1 = Invoke-ScrambleValue -Value 'TestValue' -Seed 1
        $result2 = Invoke-ScrambleValue -Value 'TestValue' -Seed 2
        if ($result1 -eq $result2) { throw "Different seeds produced identical output" }
    }

    It 'Handles empty string without error' {
        $result = Invoke-ScrambleValue -Value '' -Seed 42
        Assert-Equal '' $result
    }

    It 'Preserves mixed special characters' {
        $result = Invoke-ScrambleValue -Value 'user@host.com (555) 123-4567' -Seed 42
        Assert-Match $result '^[a-z]{4}@[a-z]{4}\.[a-z]{3} \(\d{3}\) \d{3}-\d{4}$'
    }
}

# ============================================================================
# Invoke-WrapLine Tests
# ============================================================================
Describe 'Invoke-WrapLine' {
    It 'Returns line unchanged when shorter than column' {
        Assert-Equal 'short' (Invoke-WrapLine -Line 'short' -Column 76)
    }

    It 'Returns line unchanged when equal to column' {
        $line = 'a' * 76
        Assert-Equal $line (Invoke-WrapLine -Line $line -Column 76)
    }

    It 'Wraps line longer than column' {
        $line = 'a' * 100
        $result = Invoke-WrapLine -Line $line -Column 76
        $lines = $result -split "`r?`n"
        Assert-Equal 76 $lines[0].Length
        Assert-Match $lines[1] '^ '
    }

    It 'Returns line unchanged when column is 0' {
        $line = 'a' * 200
        Assert-Equal $line (Invoke-WrapLine -Line $line -Column 0)
    }

    It 'Continuation lines start with a space' {
        $line = 'a' * 160
        $result = Invoke-WrapLine -Line $line -Column 76
        $lines = $result -split "`r?`n"
        for ($i = 1; $i -lt $lines.Count; $i++) {
            if ($lines[$i]) {
                Assert-Equal ' ' $lines[$i][0] -Message "Line $i"
            }
        }
    }

    It 'Preserves all characters across wrapped output' {
        $line = 'abcdefghij' * 10
        $result = Invoke-WrapLine -Line $line -Column 20
        $lines = $result -split "`r?`n"
        $reconstructed = $lines[0]
        for ($i = 1; $i -lt $lines.Count; $i++) {
            if ($lines[$i]) { $reconstructed += $lines[$i].Substring(1) }
        }
        Assert-Equal $line $reconstructed
    }

    It 'Returns line unchanged when column is 1' {
        Assert-Equal 'abcdef' (Invoke-WrapLine -Line 'abcdef' -Column 1)
    }
}

# ============================================================================
# Test-NeedsBase64 Tests
# ============================================================================
Describe 'Test-NeedsBase64' {
    It 'Returns false for simple ASCII string' {
        Assert-False (Test-NeedsBase64 -Value 'hello world')
    }

    It 'Returns false for null' {
        Assert-False (Test-NeedsBase64 -Value $null)
    }

    It 'Returns false for empty string' {
        Assert-False (Test-NeedsBase64 -Value '')
    }

    It 'Returns true for string starting with space' {
        Assert-True (Test-NeedsBase64 -Value ' hello')
    }

    It 'Returns true for string starting with colon' {
        Assert-True (Test-NeedsBase64 -Value ':value')
    }

    It 'Returns true for string starting with less-than' {
        Assert-True (Test-NeedsBase64 -Value '<value')
    }

    It 'Returns true for string ending with space' {
        Assert-True (Test-NeedsBase64 -Value 'hello ')
    }

    It 'Returns true for non-ASCII characters' {
        Assert-True (Test-NeedsBase64 -Value ([char]0x00E9 + 'llo'))
    }

    It 'Returns true for control characters' {
        Assert-True (Test-NeedsBase64 -Value "hello`nworld")
    }

    It 'Returns false for printable ASCII DN' {
        Assert-False (Test-NeedsBase64 -Value 'cn=John Doe,ou=Users,dc=example,dc=com')
    }
}

# ============================================================================
# Format-CsvField Tests
# ============================================================================
Describe 'Format-CsvField' {
    It 'Returns empty string for null input' {
        Assert-Equal '' (Format-CsvField -Value $null)
    }

    It 'Returns empty string for empty input' {
        Assert-Equal '' (Format-CsvField -Value '')
    }

    It 'Returns simple value unquoted' {
        Assert-Equal 'hello' (Format-CsvField -Value 'hello')
    }

    It 'Quotes values containing commas' {
        Assert-Equal '"hello,world"' (Format-CsvField -Value 'hello,world')
    }

    It 'Quotes and escapes double quotes' {
        Assert-Equal '"say ""hi"""' (Format-CsvField -Value 'say "hi"')
    }

    It 'Quotes values containing newlines' {
        Assert-Equal "`"line1`nline2`"" (Format-CsvField -Value "line1`nline2")
    }

    It 'Returns simple alphanumeric unquoted' {
        Assert-Equal 'abc123' (Format-CsvField -Value 'abc123')
    }
}

# ============================================================================
# Format-LdifOutput Tests
# ============================================================================
Describe 'Format-LdifOutput' {
    It 'Outputs version header when not terse' {
        $entries = @([ordered]@{ dn = 'cn=test,dc=example,dc=com'; cn = @('test') })
        $result = Format-LdifOutput -Entries $entries -WrapCol 76
        Assert-Match $result '^version: 1'
    }

    It 'Omits version header in terse mode' {
        $entries = @([ordered]@{ dn = 'cn=test,dc=example,dc=com'; cn = @('test') })
        $result = Format-LdifOutput -Entries $entries -WrapCol 76 -Terse
        Assert-NotMatch $result 'version: 1'
    }

    It 'Outputs dn line for each entry' {
        $entries = @(
            [ordered]@{ dn = 'cn=user1,dc=example,dc=com'; cn = @('user1') }
            [ordered]@{ dn = 'cn=user2,dc=example,dc=com'; cn = @('user2') }
        )
        $result = Format-LdifOutput -Entries $entries -WrapCol 76 -Terse
        $dnCount = ([regex]::Matches($result, '(?m)^dn: ')).Count
        Assert-Equal 2 $dnCount
    }

    It 'Outputs attributes with correct format' {
        $entries = @([ordered]@{ dn = 'cn=test,dc=com'; cn = @('test'); mail = @('test@example.com') })
        $result = Format-LdifOutput -Entries $entries -WrapCol 76 -Terse
        Assert-Match $result 'cn: test'
        Assert-Match $result 'mail: test@example.com'
    }

    It 'Handles multi-valued attributes' {
        $entries = @([ordered]@{ dn = 'cn=test,dc=com'; mail = @('a@test.com', 'b@test.com') })
        $result = Format-LdifOutput -Entries $entries -WrapCol 76 -Terse
        Assert-Match $result 'mail: a@test.com'
        Assert-Match $result 'mail: b@test.com'
    }

    It 'Base64-encodes values needing it' {
        $entries = @([ordered]@{ dn = 'cn=test,dc=com'; description = @(' starts with space') })
        $result = Format-LdifOutput -Entries $entries -WrapCol 76 -Terse
        Assert-Match $result 'description:: '
    }

    It 'Does not wrap when -NoWrap is set' {
        $longVal = 'a' * 200
        $entries = @([ordered]@{ dn = 'cn=test,dc=com'; description = @($longVal) })
        $result = Format-LdifOutput -Entries $entries -WrapCol 76 -NoWrap -Terse
        $lines = $result -split "`r?`n"
        $hasContinuation = $false
        for ($i = 1; $i -lt $lines.Count; $i++) {
            if ($lines[$i] -match '^ [^ ]') { $hasContinuation = $true; break }
        }
        Assert-False $hasContinuation
    }

    It 'Handles entry with no attributes' {
        $entries = @([ordered]@{ dn = 'cn=empty,dc=com' })
        $result = Format-LdifOutput -Entries $entries -WrapCol 76 -Terse
        Assert-Match $result 'dn: cn=empty,dc=com'
    }
}

# ============================================================================
# Format-JsonOutput Tests
# ============================================================================
Describe 'Format-JsonOutput' {
    It 'Returns valid JSON array for single entry' {
        $entries = @([ordered]@{ dn = 'cn=test,dc=com'; cn = @('test') })
        $result = Format-JsonOutput -Entries $entries
        $parsed = $result | ConvertFrom-Json
        Assert-Equal 1 @($parsed).Count
    }

    It 'Returns valid JSON array for multiple entries' {
        $entries = @(
            [ordered]@{ dn = 'cn=a,dc=com'; cn = @('a') }
            [ordered]@{ dn = 'cn=b,dc=com'; cn = @('b') }
        )
        $result = Format-JsonOutput -Entries $entries
        $parsed = $result | ConvertFrom-Json
        Assert-Equal 2 @($parsed).Count
    }

    It 'Returns empty JSON array for no entries' {
        Assert-Equal '[]' (Format-JsonOutput -Entries @())
    }

    It 'Preserves multi-valued attributes as arrays' {
        $entries = @([ordered]@{ dn = 'cn=test,dc=com'; mail = @('a@test.com', 'b@test.com') })
        $result = Format-JsonOutput -Entries $entries
        $parsed = @($result | ConvertFrom-Json)
        Assert-Equal 2 @($parsed[0].mail).Count
    }

    It 'Preserves single-valued attributes as scalars' {
        $entries = @([ordered]@{ dn = 'cn=test,dc=com'; cn = @('test') })
        $result = Format-JsonOutput -Entries $entries
        $parsed = @($result | ConvertFrom-Json)
        Assert-Equal 'test' $parsed[0].cn
    }
}

# ============================================================================
# Format-CsvOutput Tests
# ============================================================================
Describe 'Format-CsvOutput' {
    It 'Outputs header row with column names' {
        $entries = @([ordered]@{ dn = 'cn=test,dc=com'; cn = @('test'); mail = @('t@t.com') })
        $lines = (Format-CsvOutput -Entries $entries -Columns @('cn','mail')) -split "`r?`n" | Where-Object { $_ }
        Assert-Equal 'cn,mail' $lines[0]
    }

    It 'Outputs data row with correct values' {
        $entries = @([ordered]@{ dn = 'cn=test,dc=com'; cn = @('John'); mail = @('john@t.com') })
        $lines = (Format-CsvOutput -Entries $entries -Columns @('cn','mail')) -split "`r?`n" | Where-Object { $_ }
        Assert-Equal 'John,john@t.com' $lines[1]
    }

    It 'Uses only first value for single-valued CSV' {
        $entries = @([ordered]@{ dn = 'cn=test,dc=com'; mail = @('a@t.com', 'b@t.com') })
        $lines = (Format-CsvOutput -Entries $entries -Columns @('mail')) -split "`r?`n" | Where-Object { $_ }
        Assert-Equal 'a@t.com' $lines[1]
    }

    It 'Joins multi-valued with pipe in multi-valued mode' {
        $entries = @([ordered]@{ dn = 'cn=test,dc=com'; mail = @('a@t.com', 'b@t.com') })
        $lines = @((Format-CsvOutput -Entries $entries -Columns @('mail') -MultiValued) -split "`r?`n" | Where-Object { $_ })
        Assert-Equal 'a@t.com|b@t.com' $lines[1]
    }

    It 'Handles missing attributes as empty' {
        $entries = @([ordered]@{ dn = 'cn=test,dc=com'; cn = @('test') })
        $lines = (Format-CsvOutput -Entries $entries -Columns @('cn','mail')) -split "`r?`n" | Where-Object { $_ }
        Assert-Equal 'test,' $lines[1]
    }

    It 'Handles no entries (header only)' {
        $lines = @((Format-CsvOutput -Entries @() -Columns @('cn','mail')) -split "`r?`n" | Where-Object { $_ })
        Assert-Equal 1 $lines.Count
        Assert-Equal 'cn,mail' $lines[0]
    }
}

# ============================================================================
# Format-TabOutput Tests
# ============================================================================
Describe 'Format-TabOutput' {
    It 'Uses tab as delimiter' {
        $entries = @([ordered]@{ dn = 'cn=test,dc=com'; cn = @('John'); mail = @('john@t.com') })
        $lines = (Format-TabOutput -Entries $entries -Columns @('cn','mail')) -split "`r?`n" | Where-Object { $_ }
        Assert-Equal "cn`tmail" $lines[0]
        Assert-Equal "John`tjohn@t.com" $lines[1]
    }
}

# ============================================================================
# Format-DnsOnlyOutput Tests
# ============================================================================
Describe 'Format-DnsOnlyOutput' {
    It 'Outputs only DNs' {
        $entries = @(
            [ordered]@{ dn = 'cn=a,dc=com'; cn = @('a') }
            [ordered]@{ dn = 'cn=b,dc=com'; cn = @('b') }
        )
        $lines = (Format-DnsOnlyOutput -Entries $entries) -split "`r?`n" | Where-Object { $_ }
        Assert-Equal 2 $lines.Count
        Assert-Equal 'cn=a,dc=com' $lines[0]
        Assert-Equal 'cn=b,dc=com' $lines[1]
    }

    It 'Handles no entries' {
        $lines = (Format-DnsOnlyOutput -Entries @()) -split "`r?`n" | Where-Object { $_ }
        Assert-Equal 0 @($lines).Count
    }
}

# ============================================================================
# Format-ValuesOnlyOutput Tests
# ============================================================================
Describe 'Format-ValuesOnlyOutput' {
    It 'Outputs only values without attribute names or DN' {
        $entries = @([ordered]@{ dn = 'cn=test,dc=com'; cn = @('John'); mail = @('john@t.com') })
        $lines = (Format-ValuesOnlyOutput -Entries $entries) -split "`r?`n" | Where-Object { $_ }
        Assert-Contains $lines 'John'
        Assert-Contains $lines 'john@t.com'
        if ($lines -contains 'cn=test,dc=com') { throw "DN should not appear in values-only output" }
    }

    It 'Outputs multi-valued attributes as separate lines' {
        $entries = @([ordered]@{ dn = 'cn=test,dc=com'; mail = @('a@t.com', 'b@t.com') })
        $lines = (Format-ValuesOnlyOutput -Entries $entries) -split "`r?`n" | Where-Object { $_ }
        Assert-Equal 2 $lines.Count
    }

    It 'Handles no entries' {
        $lines = (Format-ValuesOnlyOutput -Entries @()) -split "`r?`n" | Where-Object { $_ }
        Assert-Equal 0 @($lines).Count
    }
}

# ============================================================================
# Get-SortControls Tests
# ============================================================================
Describe 'Get-SortControls' {
    It 'Parses simple ascending sort' {
        $ctrl = Get-SortControls -SortOrderString 'cn'
        Assert-NotNull $ctrl
        Assert-Equal 'cn' $ctrl.SortKeys[0].AttributeName
        Assert-False $ctrl.SortKeys[0].ReverseOrder
    }

    It 'Parses descending sort with minus prefix' {
        $ctrl = Get-SortControls -SortOrderString '-sn'
        Assert-Equal 'sn' $ctrl.SortKeys[0].AttributeName
        Assert-True $ctrl.SortKeys[0].ReverseOrder
    }

    It 'Parses ascending sort with plus prefix' {
        $ctrl = Get-SortControls -SortOrderString '+cn'
        Assert-Equal 'cn' $ctrl.SortKeys[0].AttributeName
        Assert-False $ctrl.SortKeys[0].ReverseOrder
    }

    It 'Parses multiple sort keys' {
        $ctrl = Get-SortControls -SortOrderString '+cn,-sn'
        Assert-Equal 2 $ctrl.SortKeys.Count
        Assert-Equal 'cn' $ctrl.SortKeys[0].AttributeName
        Assert-Equal 'sn' $ctrl.SortKeys[1].AttributeName
        Assert-True $ctrl.SortKeys[1].ReverseOrder
    }

    It 'Parses sort with matching rule' {
        $ctrl = Get-SortControls -SortOrderString 'cn:2.5.13.3'
        Assert-Equal 'cn' $ctrl.SortKeys[0].AttributeName
        Assert-Equal '2.5.13.3' $ctrl.SortKeys[0].MatchingRule
    }
}

# ============================================================================
# Read-FiltersFromFile Tests
# ============================================================================
Describe 'Read-FiltersFromFile' {
    It 'Reads filters from file, skipping comments and blanks' {
        $filterPath = Join-Path $env:TEMP 'psldap_test_filters.txt'
        @('# comment', '(objectClass=user)', '', '   ', '# another', '(sAMAccountName=jdoe)') | Set-Content -Path $filterPath
        $result = @(Read-FiltersFromFile -Path $filterPath)
        Assert-Equal 2 $result.Count
        Assert-Equal '(objectClass=user)' $result[0]
        Assert-Equal '(sAMAccountName=jdoe)' $result[1]
        Remove-Item $filterPath -Force
    }

    It 'Returns empty array for file with only comments' {
        $filterPath = Join-Path $env:TEMP 'psldap_test_comments.txt'
        @('# comment1', '# comment2') | Set-Content -Path $filterPath
        $result = @(Read-FiltersFromFile -Path $filterPath)
        Assert-Equal 0 $result.Count
        Remove-Item $filterPath -Force
    }
}

# ============================================================================
# Read-SearchSpecsFromLdapURLFile Tests
# ============================================================================
Describe 'Read-SearchSpecsFromLdapURLFile' {
    It 'Parses LDAP URLs correctly' {
        $urlPath = Join-Path $env:TEMP 'psldap_test_urls.txt'
        @('ldap://host:389/dc=example,dc=com?cn,mail?sub?(objectClass=user)') | Set-Content -Path $urlPath
        $result = @(Read-SearchSpecsFromLdapURLFile -Path $urlPath)
        Assert-Equal 1 $result.Count
        Assert-Equal 'dc=example,dc=com' $result[0].baseDN
        Assert-Contains $result[0].attributes 'cn'
        Assert-Contains $result[0].attributes 'mail'
        Assert-Equal 'sub' $result[0].scope
        Assert-Equal '(objectClass=user)' $result[0].filter
        Remove-Item $urlPath -Force
    }

    It 'Skips comment lines and blanks' {
        $urlPath = Join-Path $env:TEMP 'psldap_test_urls2.txt'
        @('# comment', '', 'ldap://host/dc=test?cn?base?(cn=foo)') | Set-Content -Path $urlPath
        $result = @(Read-SearchSpecsFromLdapURLFile -Path $urlPath)
        Assert-Equal 1 $result.Count
        Remove-Item $urlPath -Force
    }

    It 'Handles URLs with missing optional parts' {
        $urlPath = Join-Path $env:TEMP 'psldap_test_urls3.txt'
        @('ldap://host/dc=test') | Set-Content -Path $urlPath
        $result = @(Read-SearchSpecsFromLdapURLFile -Path $urlPath)
        Assert-Equal 1 $result.Count
        Assert-Equal 'dc=test' $result[0].baseDN
        Remove-Item $urlPath -Force
    }

    It 'Handles ldaps:// scheme' {
        $urlPath = Join-Path $env:TEMP 'psldap_test_urls4.txt'
        @('ldaps://host:636/dc=example,dc=com?cn?sub?(cn=test)') | Set-Content -Path $urlPath
        $result = @(Read-SearchSpecsFromLdapURLFile -Path $urlPath)
        Assert-Equal 1 $result.Count
        Assert-Equal 'dc=example,dc=com' $result[0].baseDN
        Remove-Item $urlPath -Force
    }
}

# ============================================================================
# Write-SearchOutput Tests
# ============================================================================
Describe 'Write-SearchOutput' {
    It 'Writes to file when outputFile is specified' {
        $outPath = Join-Path $env:TEMP 'psldap_test_output.ldif'
        $entries = @([ordered]@{ dn = 'cn=test,dc=com'; cn = @('test') })
        Write-SearchOutput -Entries $entries -Format 'LDIF' -WrapCol 76 -OutFile $outPath
        Assert-True (Test-Path $outPath)
        $content = Get-Content -Path $outPath -Raw
        Assert-Match $content 'dn: cn=test,dc=com'
        Remove-Item $outPath -Force
    }

    It 'Dispatches to dns-only format correctly' {
        $entries = @([ordered]@{ dn = 'cn=test,dc=com'; cn = @('test') })
        $result = Write-SearchOutput -Entries $entries -Format 'dns-only' -WrapCol 76
        Assert-Match ($result -join '') 'cn=test,dc=com'
    }
}

# ============================================================================
# Scramble unicode edge case
# ============================================================================
Describe 'Read-SearchSpecsFromLdapURLFile - Filter Validation' {
    It 'Skips URLs with invalid filters' {
        $urlPath = Join-Path $env:TEMP 'psldap_test_urls_bad.txt'
        @(
            'ldap://host/dc=test?cn?sub?(objectClass=user)'
            'ldap://host/dc=test?cn?sub?BADFILTER'
        ) | Set-Content -Path $urlPath
        $result = @(Read-SearchSpecsFromLdapURLFile -Path $urlPath)
        Assert-Equal 1 $result.Count
        Assert-Equal '(objectClass=user)' $result[0].filter
        Remove-Item $urlPath -Force
    }
}

Describe 'Read-FiltersFromFile - Filter Validation' {
    It 'Skips invalid filters from file' {
        $filterPath = Join-Path $env:TEMP 'psldap_test_badfilters.txt'
        @('(objectClass=user)', 'not-a-filter', '(cn=test)') | Set-Content -Path $filterPath
        $result = @(Read-FiltersFromFile -Path $filterPath)
        Assert-Equal 2 $result.Count
        Assert-Equal '(objectClass=user)' $result[0]
        Assert-Equal '(cn=test)' $result[1]
        Remove-Item $filterPath -Force
    }
}

Describe 'Edge Cases' {
    It 'Invoke-ScrambleValue preserves dash and exclamation in unicode string' {
        $result = Invoke-ScrambleValue -Value 'abcd-123!' -Seed 42
        Assert-Equal '-' $result[4]
        Assert-Equal '!' $result[-1]
    }

    It 'Format-LdifOutput Base64-encodes DN that needs encoding' {
        $entries = @([ordered]@{ dn = ' cn=leading space,dc=com'; cn = @('test') })
        $result = Format-LdifOutput -Entries $entries -WrapCol 76 -Terse
        Assert-Match $result '(?m)^dn:: '
        $expected = [Convert]::ToBase64String([System.Text.Encoding]::UTF8.GetBytes(' cn=leading space,dc=com'))
        Assert-Match $result ([regex]::Escape($expected))
    }

    It 'Format-LdifOutput emits plain dn: for printable ASCII DN' {
        $entries = @([ordered]@{ dn = 'cn=plain,dc=com'; cn = @('test') })
        $result = Format-LdifOutput -Entries $entries -WrapCol 76 -Terse
        Assert-Match $result '(?m)^dn: cn=plain,dc=com'
        Assert-NotMatch $result '(?m)^dn:: '
    }

    It 'Format-JsonOutput handles entries with empty attribute arrays' {
        $entries = @([ordered]@{ dn = 'cn=test,dc=com'; cn = @() })
        $result = Format-JsonOutput -Entries $entries
        Assert-NotNull $result
    }

    It 'Test-NeedsBase64 returns true for NUL byte' {
        Assert-True (Test-NeedsBase64 -Value "test`0value")
    }

    It 'Test-LdapFilter rejects filter with only whitespace' {
        Assert-False (Test-LdapFilter -Filter '   ')
    }

    It 'Invoke-WrapLine handles exact multiples of column width' {
        $line = 'a' * 152  # exactly 2x76
        $result = Invoke-WrapLine -Line $line -Column 76
        $lines = $result -split "`r?`n"
        Assert-Equal 76 $lines[0].Length
        # second line: space + 75 chars = 76
        if ($lines[1]) { Assert-Equal ' ' $lines[1][0] }
    }
}

# ============================================================================
# Regression Tests
# ----------------------------------------------------------------------------
# Tests targeting specific past regressions. Failures here indicate that a
# previously-fixed bug has come back.
# ============================================================================
Describe 'Regression Tests' {
    It 'Write-SearchOutput writes UTF-8 without BOM to output file' {
        # Regression: Out-File -Encoding UTF8 emits a BOM on Windows
        # PowerShell 5.1, which RFC 2849 forbids and many CSV consumers
        # mis-parse. Fixed by routing through [IO.File]::WriteAllText
        # with UTF8Encoding($false).
        $outPath = Join-Path $env:TEMP 'psldap_test_bom.ldif'
        try {
            $entries = @([ordered]@{ dn = 'cn=test,dc=com'; cn = @('test') })
            Write-SearchOutput -Entries $entries -Format 'LDIF' -WrapCol 76 -OutFile $outPath
            $bytes = [System.IO.File]::ReadAllBytes($outPath)
            Assert-True ($bytes.Length -ge 3) "Output file is too short to inspect for BOM"
            $hasBom = ($bytes[0] -eq 0xEF -and $bytes[1] -eq 0xBB -and $bytes[2] -eq 0xBF)
            Assert-False $hasBom "Output file unexpectedly contains UTF-8 BOM"
        }
        finally {
            if (Test-Path $outPath) { Remove-Item $outPath -Force }
        }
    }

    It 'Invoke-ScrambleValue is deterministic across separate PowerShell processes' {
        # Regression: String.GetHashCode() is randomized per process on
        # .NET Core / PowerShell 7+, so scrambled output differed across
        # runs. Fixed by hashing through Get-StableStringHash (MD5).
        # This test spawns a fresh PowerShell process and verifies the
        # same input produces the same output. If anyone reverts to
        # GetHashCode(), this assertion will fail under PS 7+.
        $pwshExe = (Get-Process -Id $PID).Path
        Assert-NotNull $pwshExe "Could not resolve current PowerShell executable"

        $scriptPath = Join-Path $PSScriptRoot 'psldap.ps1'
        $localResult = Invoke-ScrambleValue -Value 'TestValue123' -Seed 42

        $inner = ". '$scriptPath'; Invoke-ScrambleValue -Value 'TestValue123' -Seed 42"
        $encoded = [Convert]::ToBase64String([System.Text.Encoding]::Unicode.GetBytes($inner))
        $remoteResult = (& $pwshExe -NoProfile -NoLogo -EncodedCommand $encoded | Out-String).Trim()
        # Surface child-process failures with a clear message instead of
        # letting the value comparison fail with "Expected X, Got ''".
        Assert-Equal 0 $LASTEXITCODE "Child PowerShell process exited non-zero. Output: $remoteResult"

        Assert-Equal $localResult $remoteResult "Scramble output differs across processes"
    }
}
