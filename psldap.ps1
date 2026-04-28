<#
.SYNOPSIS
    Query LDAP based on a custom filter and return specified attributes.
    A PowerShell implementation inspired by the ldapsearch command-line tool.

.DESCRIPTION
    This script allows a user to query any LDAP directory server using custom filters,
    scopes, and attribute selections. It supports SSL/TLS, StartTLS, paged results,
    server-side sorting, multiple output formats (LDIF, JSON, CSV, tab-delimited, etc.),
    entry transformations (exclude, redact, scramble), and many other features modeled
    after the ldapsearch CLI tool.

    Uses System.DirectoryServices.Protocols for full LDAP protocol control.

.PARAMETER hostname
    The IP address or resolvable name of the LDAP server. Default: auto-detect from
    current AD domain, or 'localhost' if not domain-joined.

.PARAMETER port
    The port to connect to. Default: 389 (or 636 if -useSSL is specified).

.PARAMETER bindDN
    The DN to use for simple authentication.

.PARAMETER bindPassword
    The password for simple authentication as a SecureString.
    Use (ConvertTo-SecureString 'pass' -AsPlainText -Force) or (Read-Host -AsSecureString).

.PARAMETER bindPasswordFile
    Path to a file containing the bind password (first line is used).

.PARAMETER promptForBindPassword
    Interactively prompt for the bind password.

.PARAMETER useSSL
    Use SSL (LDAPS) when communicating with the directory server.

.PARAMETER useStartTLS
    Use StartTLS to upgrade a plain connection to TLS.

.PARAMETER trustAll
    Trust any certificate presented by the directory server.

.PARAMETER baseDN
    The base DN for the search. Default: derived from the domain or empty string.

.PARAMETER scope
    The search scope: base, one, sub, or subordinates. Default: sub.

.PARAMETER sizeLimit
    Maximum number of entries the server should return. 0 = no limit.

.PARAMETER timeLimitSeconds
    Maximum time in seconds for the server to process each search. 0 = no limit.

.PARAMETER dereferencePolicy
    Alias dereferencing policy: never, always, search, or find. Default: never.

.PARAMETER typesOnly
    Return only attribute names, not values.

.PARAMETER filter
    The LDAP search filter. May be specified multiple times. Default: (objectClass=*).

.PARAMETER filterFile
    Path to a file containing LDAP filters (one per line). Lines starting with '#' are ignored.

.PARAMETER ldapURLFile
    Path to a file containing LDAP URLs defining searches. Each URL specifies baseDN,
    scope, filter, and attributes. Host/port in URLs are ignored.

.PARAMETER requestedAttribute
    Attribute(s) to include in results. May be specified multiple times.

.PARAMETER followReferrals
    Follow referrals encountered during search processing.

.PARAMETER retryFailedOperations
    Automatically retry a failed search with a new connection before reporting failure.

.PARAMETER continueOnError
    Continue processing searches even if an error is encountered.

.PARAMETER ratePerSecond
    Maximum number of search requests per second.

.PARAMETER dryRun
    Display which searches would be issued without sending them.

.PARAMETER countEntries
    Exit code represents the number of entries returned (max 255).

.PARAMETER outputFormat
    Output format: LDIF, JSON, CSV, multi-valued-csv, tab-delimited,
    multi-valued-tab-delimited, dns-only, or values-only. Default: LDIF.

.PARAMETER outputFile
    Path to write search results. If not specified, results go to standard output.

.PARAMETER teeResultsToStandardOut
    Write results to both the output file and standard output.

.PARAMETER separateOutputFilePerSearch
    Generate a separate output file per search when using multiple filters.

.PARAMETER wrapColumn
    Column at which to wrap long LDIF lines. Default: 76. 0 = no wrapping.

.PARAMETER dontWrap
    Disable line wrapping in LDIF output.

.PARAMETER terse
    Suppress summary messages; only output entries and references.

.PARAMETER sortOrder
    Server-side sort order. Comma-separated list of attribute names, optionally
    prefixed with '+' (ascending) or '-' (descending).

.PARAMETER simplePageSize
    Page size for the simple paged results control. Default: 1000.

.PARAMETER excludeAttribute
    Attribute(s) to exclude from search result entries.

.PARAMETER redactAttribute
    Attribute(s) whose values should be redacted in output.

.PARAMETER hideRedactedValueCount
    When redacting, show only a single '***REDACTED***' regardless of value count.

.PARAMETER scrambleAttribute
    Attribute(s) whose values should be scrambled (deterministic substitution).

.PARAMETER scrambleRandomSeed
    Seed for the random number generator used during scrambling.

.PARAMETER requireMatch
    Exit with code 1 if the search returns no matching entries.

.EXAMPLE
    .\psldap.ps1 -hostname ldap.example.com -baseDN "dc=example,dc=com" -filter "(objectClass=user)" -requestedAttribute cn,mail

.EXAMPLE
    .\psldap.ps1 -hostname ldap.example.com -port 636 -useSSL -trustAll -bindDN "cn=admin,dc=example,dc=com" -promptForBindPassword -baseDN "dc=example,dc=com" -filter "(uid=jdoe)" -outputFormat JSON

.EXAMPLE
    .\psldap.ps1 -filterFile ./filters.txt -baseDN "dc=example,dc=com" -outputFormat CSV -requestedAttribute cn,mail,telephoneNumber -outputFile results.csv

.EXAMPLE
    .\psldap.ps1 -ldapURLFile ./urls.txt -outputFormat LDIF -continueOnError
#>

[CmdletBinding()]
param (
    # Connection
    [Alias('h')]
    [string]$hostname,

    [Alias('p')]
    [ValidateRange(0, 65535)]
    [int]$port = 0,

    [Alias('D')]
    [string]$bindDN,

    [Alias('w')]
    [SecureString]$bindPassword,

    [Alias('j')]
    [ValidateScript({
        if ($_) {
            $resolved = $ExecutionContext.SessionState.Path.GetUnresolvedProviderPathFromPSPath($_)
            if (-not (Test-Path $resolved -PathType Leaf)) { throw "Bind password file '$_' not found." }
        }
        $true
    })]
    [string]$bindPasswordFile,

    [switch]$promptForBindPassword,

    # Note: ldapsearch uses '-Z' for StartTLS, but PowerShell aliases are
    # case-insensitive — '-Z' would collide with '-z' (sizeLimit). Use the
    # full -useSSL / -useStartTLS names instead.
    [switch]$useSSL,

    [Alias('q')]
    [switch]$useStartTLS,

    [Alias('X')]
    [switch]$trustAll,

    # Search
    [Alias('b')]
    [string]$baseDN,

    [Alias('s')]
    [ValidateSet('base', 'one', 'sub', 'subordinates')]
    [string]$scope = 'sub',

    [Alias('z')]
    [ValidateRange(0, [int]::MaxValue)]
    [int]$sizeLimit = 0,

    [Alias('l')]
    [ValidateRange(0, [int]::MaxValue)]
    [int]$timeLimitSeconds = 0,

    [Alias('a')]
    [ValidateSet('never', 'always', 'search', 'find')]
    [string]$dereferencePolicy = 'never',

    # Note: ldapsearch uses '-A' for typesOnly, but PowerShell aliases are
    # case-insensitive — '-A' would collide with '-a' (dereferencePolicy).
    # Use the full -typesOnly name instead.
    [switch]$typesOnly,

    [string[]]$filter,

    [Alias('f')]
    [ValidateScript({
        if ($_) {
            $resolved = $ExecutionContext.SessionState.Path.GetUnresolvedProviderPathFromPSPath($_)
            if (-not (Test-Path $resolved -PathType Leaf)) { throw "Filter file '$_' not found." }
        }
        $true
    })]
    [string]$filterFile,

    [ValidateScript({
        if ($_) {
            $resolved = $ExecutionContext.SessionState.Path.GetUnresolvedProviderPathFromPSPath($_)
            if (-not (Test-Path $resolved -PathType Leaf)) { throw "LDAP URL file '$_' not found." }
        }
        $true
    })]
    [string]$ldapURLFile,

    [string[]]$requestedAttribute,

    [switch]$followReferrals,

    [switch]$retryFailedOperations,

    [Alias('c')]
    [switch]$continueOnError,

    [Alias('r')]
    [ValidateRange(0, [int]::MaxValue)]
    [int]$ratePerSecond = 0,

    [Alias('n')]
    [switch]$dryRun,

    [switch]$countEntries,

    # Output
    [ValidateSet('LDIF', 'JSON', 'CSV', 'multi-valued-csv', 'tab-delimited',
        'multi-valued-tab-delimited', 'dns-only', 'values-only')]
    [string]$outputFormat = 'LDIF',

    [ValidateScript({
        if ($_) {
            $parentDir = Split-Path $_ -Parent
            if ($parentDir -and -not (Test-Path $parentDir -PathType Container)) {
                throw "Output file directory '$parentDir' does not exist."
            }
        }
        $true
    })]
    [string]$outputFile,

    [switch]$teeResultsToStandardOut,

    [switch]$separateOutputFilePerSearch,

    [ValidateRange(0, [int]::MaxValue)]
    [int]$wrapColumn = 76,

    [Alias('T')]
    [switch]$dontWrap,

    [switch]$terse,

    # Note: ldapsearch uses '-S' for sortOrder, but PowerShell aliases are
    # case-insensitive — '-S' would collide with '-s' (scope). Use the
    # full -sortOrder name instead.
    [string]$sortOrder,

    [ValidateRange(1, [int]::MaxValue)]
    [int]$simplePageSize = 1000,

    # Transformations
    [string[]]$excludeAttribute,

    [string[]]$redactAttribute,

    [switch]$hideRedactedValueCount,

    [string[]]$scrambleAttribute,

    [int]$scrambleRandomSeed = 0,

    [switch]$requireMatch
)

# ============================================================================
# Assembly loading
# ============================================================================
Add-Type -AssemblyName System.DirectoryServices.Protocols
Add-Type -AssemblyName System.Net

# ============================================================================
# Helper Functions
# ============================================================================

function Get-BindCredential {
    <#
    .SYNOPSIS
        Resolves bind credentials from the various input options.
        Returns a PSCredential or $null. Passwords are handled as SecureString
        throughout and never held in plaintext longer than necessary.
    #>
    [SecureString]$securePass = $null

    if ($script:promptForBindPassword) {
        $securePass = Read-Host -Prompt "Enter bind password" -AsSecureString
    }
    elseif ($script:bindPasswordFile) {
        # Build SecureString character-by-character to avoid plaintext string allocation
        $securePass = [System.Security.SecureString]::new()
        $fileBytes = [System.IO.File]::ReadAllBytes($script:bindPasswordFile)
        try {
            # Find first line (stop at CR or LF)
            $lineEnd = $fileBytes.Length
            for ($i = 0; $i -lt $fileBytes.Length; $i++) {
                if ($fileBytes[$i] -eq 0x0A -or $fileBytes[$i] -eq 0x0D) {
                    $lineEnd = $i
                    break
                }
            }
            # Trim leading/trailing whitespace, decode as UTF-8, append char by char
            $lineChars = [System.Text.Encoding]::UTF8.GetChars($fileBytes, 0, $lineEnd)
            $trimStart = 0
            $trimEnd = $lineChars.Length - 1
            while ($trimStart -le $trimEnd -and [char]::IsWhiteSpace($lineChars[$trimStart])) { $trimStart++ }
            while ($trimEnd -ge $trimStart -and [char]::IsWhiteSpace($lineChars[$trimEnd])) { $trimEnd-- }
            for ($i = $trimStart; $i -le $trimEnd; $i++) {
                $securePass.AppendChar($lineChars[$i])
            }
            $securePass.MakeReadOnly()
        }
        finally {
            # Zero out the byte and char arrays to remove password from memory
            [Array]::Clear($fileBytes, 0, $fileBytes.Length)
            if ($lineChars) { [Array]::Clear($lineChars, 0, $lineChars.Length) }
        }
    }
    elseif ($script:bindPassword) {
        $securePass = $script:bindPassword
    }

    if ($securePass) {
        return [System.Net.NetworkCredential]::new($script:bindDN, $securePass)
    }
    return $null
}

function New-LdapConnection {
    <#
    .SYNOPSIS
        Creates and configures an LdapConnection.
    #>
    param(
        [string]$Server,
        [int]$ServerPort,
        [System.Net.NetworkCredential]$Credential
    )

    $identifier = [System.DirectoryServices.Protocols.LdapDirectoryIdentifier]::new($Server, $ServerPort)
    if ($Credential) {
        $conn = [System.DirectoryServices.Protocols.LdapConnection]::new($identifier, $Credential)
        $conn.AuthType = [System.DirectoryServices.Protocols.AuthType]::Basic
    }
    else {
        $conn = [System.DirectoryServices.Protocols.LdapConnection]::new($identifier)
        $conn.AuthType = [System.DirectoryServices.Protocols.AuthType]::Negotiate
    }

    $conn.SessionOptions.ProtocolVersion = 3

    if ($script:trustAll) {
        $conn.SessionOptions.VerifyServerCertificate = {
            param($connection, $certificate)
            return $true
        }
    }

    if ($script:useSSL) {
        $conn.SessionOptions.SecureSocketLayer = $true
    }

    if ($script:followReferrals) {
        $conn.SessionOptions.ReferralChasing = [System.DirectoryServices.Protocols.ReferralChasingOptions]::All
    }
    else {
        $conn.SessionOptions.ReferralChasing = [System.DirectoryServices.Protocols.ReferralChasingOptions]::None
    }

    try {
        if ($script:useStartTLS) {
            $conn.SessionOptions.StartTransportLayerSecurity($null)
        }

        $conn.Bind()
    }
    catch {
        $conn.Dispose()
        throw
    }

    return $conn
}

function Test-LdapFilter {
    <#
    .SYNOPSIS
        Basic validation that a string looks like a valid LDAP filter.
        Checks balanced parentheses and non-empty content.
    #>
    param([string]$Filter)

    if ([string]::IsNullOrWhiteSpace($Filter)) { return $false }
    if ($Filter[0] -ne '(') { return $false }
    if ($Filter[-1] -ne ')') { return $false }

    $depth = 0
    foreach ($ch in $Filter.ToCharArray()) {
        if ($ch -eq '(') { $depth++ }
        elseif ($ch -eq ')') { $depth-- }
        if ($depth -lt 0) { return $false }
    }
    return ($depth -eq 0)
}

function Read-FiltersFromFile {
    <#
    .SYNOPSIS
        Reads LDAP filters from a file, one per line. Ignores blank lines and comments.
        Validates basic filter syntax.
    #>
    param([string]$Path)

    $filters = @()
    $lineNum = 0
    foreach ($line in (Get-Content -Path $Path)) {
        $lineNum++
        $trimmed = $line.Trim()
        if ($trimmed -and -not $trimmed.StartsWith('#')) {
            if (-not (Test-LdapFilter -Filter $trimmed)) {
                Write-Warning "Skipping invalid filter at line ${lineNum}: $trimmed"
                continue
            }
            $filters += $trimmed
        }
    }
    return $filters
}

function Read-SearchSpecsFromLdapURLFile {
    <#
    .SYNOPSIS
        Parses LDAP URLs from a file and returns search spec hashtables.
        Format: ldap://host:port/baseDN?attributes?scope?filter
    #>
    param([string]$Path)

    $specs = @()
    foreach ($line in (Get-Content -Path $Path)) {
        $trimmed = $line.Trim()
        if (-not $trimmed -or $trimmed.StartsWith('#')) { continue }

        # Remove scheme
        $url = $trimmed -replace '^ldaps?://', ''

        # Split host:port from the rest
        $slashIdx = $url.IndexOf('/')
        if ($slashIdx -lt 0) { continue }

        $remainder = $url.Substring($slashIdx + 1)

        # Split by '?': baseDN?attributes?scope?filter
        $parts = $remainder.Split('?')

        $parsedFilter = $(if ($parts.Count -ge 4 -and $parts[3]) { [Uri]::UnescapeDataString($parts[3]) } else { $null })

        # Validate filter from URL if present
        if ($parsedFilter -and -not (Test-LdapFilter -Filter $parsedFilter)) {
            Write-Warning "Skipping LDAP URL with invalid filter: $parsedFilter"
            continue
        }

        $spec = @{
            baseDN     = $(if ($parts.Count -ge 1 -and $parts[0]) { [Uri]::UnescapeDataString($parts[0]) } else { $null })
            attributes = $(if ($parts.Count -ge 2 -and $parts[1]) { $parts[1].Split(',') } else { $null })
            scope      = $(if ($parts.Count -ge 3 -and $parts[2]) { $parts[2] } else { $null })
            filter     = $parsedFilter
        }
        $specs += $spec
    }
    return $specs
}

function ConvertTo-TransformedEntry {
    <#
    .SYNOPSIS
        Converts a SearchResultEntry to an ordered dictionary, applying transformations.
    #>
    param(
        [System.DirectoryServices.Protocols.SearchResultEntry]$Entry,
        [string[]]$ExcludeAttributes,
        [string[]]$RedactAttributes,
        [switch]$HideRedactedCount,
        [string[]]$ScrambleAttributes,
        [int]$ScrambleSeed
    )

    $result = [ordered]@{
        dn = $Entry.DistinguishedName
    }

    foreach ($attrName in $Entry.Attributes.AttributeNames) {
        $attrNameLower = $attrName.ToLower()

        # Exclude check
        if ($ExcludeAttributes -and ($ExcludeAttributes | Where-Object { $_.ToLower() -eq $attrNameLower })) {
            continue
        }

        $values = @()
        $attr = $Entry.Attributes[$attrName]
        for ($i = 0; $i -lt $attr.Count; $i++) {
            $val = $attr[$i]
            if ($val -is [byte[]]) {
                $values += [Convert]::ToBase64String($val)
            }
            else {
                $values += $val.ToString()
            }
        }

        # Redact check
        if ($RedactAttributes -and ($RedactAttributes | Where-Object { $_.ToLower() -eq $attrNameLower })) {
            if ($HideRedactedCount) {
                $values = @('***REDACTED***')
            }
            else {
                if ($values.Count -eq 1) {
                    $values = @('***REDACTED***')
                }
                else {
                    $values = @(1..$values.Count | ForEach-Object { "***REDACTED$_***" })
                }
            }
        }
        # Scramble check
        elseif ($ScrambleAttributes -and ($ScrambleAttributes | Where-Object { $_.ToLower() -eq $attrNameLower })) {
            $values = $values | ForEach-Object { Invoke-ScrambleValue -Value $_ -Seed $ScrambleSeed }
        }

        $result[$attrName] = $values
    }

    return $result
}

# ----------------------------------------------------------------------------
# MD5 capability detection & instance cache for Get-StableStringHash.
#
# Option C from issue #13: prefer the static [MD5]::HashData($bytes) method
# (PS 7.2+ / .NET 5+, allocation-free except for the result array). On
# Windows PowerShell 5.1, where HashData isn't available, fall back to a
# single cached [MD5] instance reused across calls.
#
# Both paths produce byte-identical output. The pinned regression test
# (Get-StableStringHash 'hello' = 0x2a40415d) and the cross-process
# determinism test catch any drift.
#
# Caveat (single-threaded assumption): [HashAlgorithm] is not thread-safe.
# PowerShell scripts run single-threaded by convention, but the cached
# instance MUST NOT be used from multiple runspaces concurrently
# (e.g. `ForEach-Object -Parallel`, runspace pools). If parallel scramble
# is ever added, switch to per-runspace instances or the static path
# unconditionally. See enhancement issue tracking the alternatives.
# ----------------------------------------------------------------------------
$script:_useHashDataStatic = ([System.Security.Cryptography.MD5].GetMethod('HashData', [Type[]]@([byte[]])) -ne $null)
$script:_md5Instance = $null

function Get-StableStringHash {
    <#
    .SYNOPSIS
        Returns a stable Int32 hash of a string. Used instead of String.GetHashCode()
        because that is randomized per-process on .NET Core / PowerShell 7+,
        which would break cross-run determinism of scrambled values.
        Uses MD5 (non-cryptographic use — just a stable mixer). Native to .NET, no module install.
    #>
    param([string]$Value)

    if ([string]::IsNullOrEmpty($Value)) { return 0 }

    $bytes = [System.Text.Encoding]::UTF8.GetBytes($Value)
    if ($script:_useHashDataStatic) {
        # PS 7.2+ / .NET 5+ path — no instance, no IDisposable, allocation-free
        # except for the returned byte[].
        $hashBytes = [System.Security.Cryptography.MD5]::HashData($bytes)
    }
    else {
        # PS 5.1 fallback — reuse a single cached MD5 instance across calls.
        # ComputeHash(byte[]) is a one-shot call that resets internal state,
        # so per-call disposal isn't needed. The instance lives for process
        # lifetime; this is fine for a CLI tool that exits cleanly.
        if (-not $script:_md5Instance) {
            $script:_md5Instance = [System.Security.Cryptography.MD5]::Create()
        }
        $hashBytes = $script:_md5Instance.ComputeHash($bytes)
    }
    return [BitConverter]::ToInt32($hashBytes, 0)
}

function Invoke-ScrambleValue {
    <#
    .SYNOPSIS
        Deterministically scrambles a string value using a seeded RNG.
        Preserves character class: letters stay letters (case preserved), digits stay digits.
    #>
    param(
        [string]$Value,
        [int]$Seed
    )

    # Combine seed with a stable hash of the value for cross-run deterministic scrambling.
    $valueHash = Get-StableStringHash -Value $Value
    $rng = [System.Random]::new($Seed -bxor $valueHash)

    $chars = $Value.ToCharArray()
    for ($i = 0; $i -lt $chars.Length; $i++) {
        $ch = $chars[$i]
        if ([char]::IsUpper($ch)) {
            $chars[$i] = [char]([int][char]'A' + $rng.Next(26))
        }
        elseif ([char]::IsLower($ch)) {
            $chars[$i] = [char]([int][char]'a' + $rng.Next(26))
        }
        elseif ([char]::IsDigit($ch)) {
            $chars[$i] = [char]([int][char]'0' + $rng.Next(10))
        }
        # else: preserve special characters
    }
    return [string]::new($chars)
}

function Invoke-WrapLine {
    <#
    .SYNOPSIS
        Wraps an LDIF line at the specified column. Continuation lines start with a space.
    #>
    param(
        [string]$Line,
        [int]$Column
    )

    if ($Column -le 1 -or $Line.Length -le $Column) {
        return $Line
    }

    $sb = [System.Text.StringBuilder]::new()
    [void]$sb.Append($Line.Substring(0, $Column))

    $pos = $Column
    while ($pos -lt $Line.Length) {
        $remaining = $Line.Length - $pos
        # Continuation lines: leading space counts as part of the column width
        $chunkSize = [Math]::Min($remaining, $Column - 1)
        [void]$sb.AppendLine()
        [void]$sb.Append(' ')
        [void]$sb.Append($Line.Substring($pos, $chunkSize))
        $pos += $chunkSize
    }

    return $sb.ToString()
}

function Test-NeedsBase64 {
    <#
    .SYNOPSIS
        Returns true if a value needs Base64 encoding in LDIF output.
    #>
    param([string]$Value)

    if ([string]::IsNullOrEmpty($Value)) { return $false }

    # Starts with space, colon, or less-than
    if ($Value[0] -eq ' ' -or $Value[0] -eq ':' -or $Value[0] -eq '<') {
        return $true
    }
    # Ends with space
    if ($Value[-1] -eq ' ') {
        return $true
    }
    # Contains non-ASCII or control characters
    foreach ($ch in $Value.ToCharArray()) {
        if ([int]$ch -lt 32 -or [int]$ch -gt 126) {
            return $true
        }
    }
    return $false
}

function Format-LdifOutput {
    <#
    .SYNOPSIS
        Formats entries as LDIF.
    #>
    param(
        [array]$Entries,
        [int]$WrapCol,
        [switch]$NoWrap,
        [switch]$Terse
    )

    $sb = [System.Text.StringBuilder]::new()

    if (-not $Terse) {
        [void]$sb.AppendLine("version: 1")
        [void]$sb.AppendLine()
    }

    foreach ($entry in $Entries) {
        if (Test-NeedsBase64 -Value $entry.dn) {
            $dnB64 = [Convert]::ToBase64String([System.Text.Encoding]::UTF8.GetBytes($entry.dn))
            $dnLine = "dn:: $dnB64"
        }
        else {
            $dnLine = "dn: $($entry.dn)"
        }
        if ($NoWrap) {
            [void]$sb.AppendLine($dnLine)
        }
        else {
            [void]$sb.AppendLine((Invoke-WrapLine -Line $dnLine -Column $WrapCol))
        }

        foreach ($key in $entry.Keys) {
            if ($key -eq 'dn') { continue }
            foreach ($val in $entry[$key]) {
                if (Test-NeedsBase64 -Value $val) {
                    $b64 = [Convert]::ToBase64String([System.Text.Encoding]::UTF8.GetBytes($val))
                    $line = "${key}:: $b64"
                }
                else {
                    $line = "${key}: $val"
                }

                if ($NoWrap) {
                    [void]$sb.AppendLine($line)
                }
                else {
                    [void]$sb.AppendLine((Invoke-WrapLine -Line $line -Column $WrapCol))
                }
            }
        }
        [void]$sb.AppendLine()
    }

    return $sb.ToString()
}

function Format-JsonOutput {
    <#
    .SYNOPSIS
        Formats entries as JSON.
    #>
    param([array]$Entries)

    $objects = @()
    foreach ($entry in $Entries) {
        $obj = [ordered]@{ dn = $entry.dn }
        foreach ($key in $entry.Keys) {
            if ($key -eq 'dn') { continue }
            $vals = $entry[$key]
            if ($vals.Count -eq 1) {
                $obj[$key] = $vals[0]
            }
            else {
                $obj[$key] = $vals
            }
        }
        $objects += [PSCustomObject]$obj
    }

    if ($objects.Count -eq 0) {
        return '[]'
    }
    elseif ($objects.Count -eq 1) {
        return '[' + ($objects[0] | ConvertTo-Json -Depth 10) + ']'
    }
    return ($objects | ConvertTo-Json -Depth 10)
}

function Format-CsvOutput {
    <#
    .SYNOPSIS
        Formats entries as CSV or multi-valued CSV.
    #>
    param(
        [array]$Entries,
        [string[]]$Columns,
        [switch]$MultiValued
    )

    $sb = [System.Text.StringBuilder]::new()

    # Header
    [void]$sb.AppendLine(($Columns | ForEach-Object { Format-CsvField $_ }) -join ',')

    foreach ($entry in $Entries) {
        $row = @()
        foreach ($col in $Columns) {
            $vals = $entry[$col]
            if (-not $vals) {
                $row += ''
            }
            elseif ($MultiValued) {
                $row += Format-CsvField (($vals) -join '|')
            }
            else {
                $row += Format-CsvField ($vals[0])
            }
        }
        [void]$sb.AppendLine($row -join ',')
    }

    return $sb.ToString()
}

function Format-CsvField {
    <#
    .SYNOPSIS
        Properly escapes a CSV field value.
    #>
    param([string]$Value)

    if ([string]::IsNullOrEmpty($Value)) { return '' }
    if ($Value -match '[,"\r\n]') {
        return '"' + ($Value -replace '"', '""') + '"'
    }
    return $Value
}

function Format-TabOutput {
    <#
    .SYNOPSIS
        Formats entries as tab-delimited output.
    #>
    param(
        [array]$Entries,
        [string[]]$Columns,
        [switch]$MultiValued
    )

    $sb = [System.Text.StringBuilder]::new()

    # Header
    [void]$sb.AppendLine($Columns -join "`t")

    foreach ($entry in $Entries) {
        $row = @()
        foreach ($col in $Columns) {
            $vals = $entry[$col]
            if (-not $vals) {
                $row += ''
            }
            elseif ($MultiValued) {
                $row += ($vals -join '|')
            }
            else {
                $row += $vals[0]
            }
        }
        [void]$sb.AppendLine($row -join "`t")
    }

    return $sb.ToString()
}

function Format-DnsOnlyOutput {
    <#
    .SYNOPSIS
        Outputs only the DN of each entry.
    #>
    param([array]$Entries)

    $sb = [System.Text.StringBuilder]::new()
    foreach ($entry in $Entries) {
        [void]$sb.AppendLine($entry.dn)
    }
    return $sb.ToString()
}

function Format-ValuesOnlyOutput {
    <#
    .SYNOPSIS
        Outputs only attribute values, one per line.
    #>
    param([array]$Entries)

    $sb = [System.Text.StringBuilder]::new()
    foreach ($entry in $Entries) {
        foreach ($key in $entry.Keys) {
            if ($key -eq 'dn') { continue }
            foreach ($val in $entry[$key]) {
                [void]$sb.AppendLine($val)
            }
        }
    }
    return $sb.ToString()
}

function Write-SearchOutput {
    <#
    .SYNOPSIS
        Dispatches to the appropriate formatter and writes output.
    #>
    param(
        [array]$Entries,
        [string]$Format,
        [string[]]$Columns,
        [string]$OutFile,
        [switch]$TeeToStdOut,
        [int]$WrapCol,
        [switch]$NoWrap,
        [switch]$Terse
    )

    $output = switch ($Format) {
        'LDIF' { Format-LdifOutput -Entries $Entries -WrapCol $WrapCol -NoWrap:$NoWrap -Terse:$Terse }
        'JSON' { Format-JsonOutput -Entries $Entries }
        'CSV' { Format-CsvOutput -Entries $Entries -Columns $Columns }
        'multi-valued-csv' { Format-CsvOutput -Entries $Entries -Columns $Columns -MultiValued }
        'tab-delimited' { Format-TabOutput -Entries $Entries -Columns $Columns }
        'multi-valued-tab-delimited' { Format-TabOutput -Entries $Entries -Columns $Columns -MultiValued }
        'dns-only' { Format-DnsOnlyOutput -Entries $Entries }
        'values-only' { Format-ValuesOnlyOutput -Entries $Entries }
    }

    if ($OutFile) {
        # UTF-8 without BOM. Out-File -Encoding UTF8 writes a BOM on Windows PowerShell 5.1,
        # which breaks LDIF (RFC 2849 mandates no BOM) and many CSV consumers.
        $resolvedPath = $ExecutionContext.SessionState.Path.GetUnresolvedProviderPathFromPSPath($OutFile)
        $utf8NoBom = [System.Text.UTF8Encoding]::new($false)
        [System.IO.File]::WriteAllText($resolvedPath, $output, $utf8NoBom)
        if ($TeeToStdOut) {
            Write-Output $output
        }
    }
    else {
        Write-Output $output
    }
}

function Get-SortControls {
    <#
    .SYNOPSIS
        Parses a sort order string and returns a SortRequestControl.
    #>
    param([string]$SortOrderString)

    $keys = @()
    foreach ($part in ($SortOrderString.Split(','))) {
        $part = $part.Trim()
        $reverse = $false
        $attrName = $part

        if ($part.StartsWith('-')) {
            $reverse = $true
            $attrName = $part.Substring(1)
        }
        elseif ($part.StartsWith('+')) {
            $attrName = $part.Substring(1)
        }

        # Check for matching rule (attr:matchingRule)
        $matchingRule = $null
        if ($attrName.Contains(':')) {
            $splitAttr = $attrName.Split(':', 2)
            $attrName = $splitAttr[0]
            $matchingRule = $splitAttr[1]
        }

        $sortKey = [System.DirectoryServices.Protocols.SortKey]::new($attrName, $matchingRule, $reverse)
        $keys += $sortKey
    }

    return [System.DirectoryServices.Protocols.SortRequestControl]::new([System.DirectoryServices.Protocols.SortKey[]]$keys)
}

function Invoke-LdapSearch {
    <#
    .SYNOPSIS
        Executes an LDAP search with paging and optional sorting.
    #>
    param(
        [System.DirectoryServices.Protocols.LdapConnection]$Connection,
        [string]$SearchBaseDN,
        [string]$SearchFilter,
        [System.DirectoryServices.Protocols.SearchScope]$SearchScope,
        [string[]]$Attributes,
        [int]$MaxResults,
        [int]$TimeLimit,
        [int]$PageSize,
        [string]$SortOrderStr,
        [string]$DerefPolicy,
        [switch]$TypesOnlyFlag,
        [switch]$DryRunFlag,
        [int]$RateLimit
    )

    if ($DryRunFlag) {
        Write-Host "[DRY RUN] Would search:"
        Write-Host "  Base DN : $SearchBaseDN"
        Write-Host "  Scope   : $SearchScope"
        Write-Host "  Filter  : $SearchFilter"
        Write-Host "  Attrs   : $($Attributes -join ', ')"
        Write-Host "  Size    : $MaxResults"
        Write-Host "  Time    : ${TimeLimit}s"
        return @()
    }

    $request = [System.DirectoryServices.Protocols.SearchRequest]::new(
        $SearchBaseDN,
        $SearchFilter,
        $SearchScope,
        $Attributes
    )

    if ($MaxResults -gt 0) {
        $request.SizeLimit = $MaxResults
    }
    if ($TimeLimit -gt 0) {
        $request.TimeLimit = [TimeSpan]::FromSeconds($TimeLimit)
    }
    $request.TypesOnly = $TypesOnlyFlag.IsPresent

    # Dereference policy
    if ($DerefPolicy) {
        $derefMap = @{
            'never'  = [System.DirectoryServices.Protocols.DereferenceAlias]::NeverDerefAliases
            'always' = [System.DirectoryServices.Protocols.DereferenceAlias]::DerefAlways
            'search' = [System.DirectoryServices.Protocols.DereferenceAlias]::DerefInSearching
            'find'   = [System.DirectoryServices.Protocols.DereferenceAlias]::DerefFindingBaseObject
        }
        $request.Aliases = $derefMap[$DerefPolicy]
    }

    # Paging control
    $pageControl = [System.DirectoryServices.Protocols.PageResultRequestControl]::new($PageSize)
    [void]$request.Controls.Add($pageControl)

    # Sort control
    if ($SortOrderStr) {
        $sortControl = Get-SortControls -SortOrderString $SortOrderStr
        [void]$request.Controls.Add($sortControl)
    }

    $allEntries = [System.Collections.Generic.List[System.DirectoryServices.Protocols.SearchResultEntry]]::new()
    $stopwatch = [System.Diagnostics.Stopwatch]::new()

    while ($true) {
        if ($RateLimit -gt 0) {
            $minInterval = 1000.0 / $RateLimit
            if ($stopwatch.IsRunning) {
                $elapsed = $stopwatch.Elapsed.TotalMilliseconds
                if ($elapsed -lt $minInterval) {
                    Start-Sleep -Milliseconds ([int]($minInterval - $elapsed))
                }
            }
            $stopwatch.Restart()
        }

        $response = $Connection.SendRequest($request)

        if ($response -isnot [System.DirectoryServices.Protocols.SearchResponse]) {
            Write-Error "Unexpected response type: $($response.GetType().Name)"
            break
        }

        foreach ($entry in $response.Entries) {
            $allEntries.Add($entry)
        }

        # Check for page response control
        $pageResponse = $null
        foreach ($ctrl in $response.Controls) {
            if ($ctrl -is [System.DirectoryServices.Protocols.PageResultResponseControl]) {
                $pageResponse = $ctrl
                break
            }
        }

        if ($pageResponse -and $pageResponse.Cookie -and $pageResponse.Cookie.Length -gt 0) {
            $pageControl.Cookie = $pageResponse.Cookie
        }
        else {
            break
        }

        # If we have a size limit and have already retrieved enough
        if ($MaxResults -gt 0 -and $allEntries.Count -ge $MaxResults) {
            break
        }
    }

    return $allEntries
}

function Invoke-SearchAndOutput {
    <#
    .SYNOPSIS
        Executes a single search, transforms entries, and writes output.
        Returns the count of entries found.
    #>
    param(
        [System.DirectoryServices.Protocols.LdapConnection]$Conn,
        [string]$BaseDN,
        [string]$Filter,
        [System.DirectoryServices.Protocols.SearchScope]$Scope,
        [string[]]$Attrs,
        [int]$SearchIndex,
        [int]$TotalSearches,
        [string]$OutFile
    )

    $rawEntries = Invoke-LdapSearch `
        -Connection $Conn `
        -SearchBaseDN $BaseDN `
        -SearchFilter $Filter `
        -SearchScope $Scope `
        -Attributes $Attrs `
        -MaxResults $script:sizeLimit `
        -TimeLimit $script:timeLimitSeconds `
        -PageSize $script:simplePageSize `
        -SortOrderStr $script:sortOrder `
        -DerefPolicy $script:dereferencePolicy `
        -TypesOnlyFlag:$script:typesOnly `
        -DryRunFlag:$script:dryRun `
        -RateLimit $script:ratePerSecond

    $transformedEntries = @()
    foreach ($rawEntry in $rawEntries) {
        $transformedEntries += ConvertTo-TransformedEntry `
            -Entry $rawEntry `
            -ExcludeAttributes $script:excludeAttribute `
            -RedactAttributes $script:redactAttribute `
            -HideRedactedCount:$script:hideRedactedValueCount `
            -ScrambleAttributes $script:scrambleAttribute `
            -ScrambleSeed $script:scrambleRandomSeed
    }

    $columns = @()
    if ($script:outputFormat -in @('CSV', 'multi-valued-csv', 'tab-delimited', 'multi-valued-tab-delimited')) {
        if ($Attrs.Count -gt 0) {
            $columns = $Attrs
        }
        else {
            # Insertion-ordered de-duplication (no LinkedHashSet in .NET).
            $seen = [System.Collections.Generic.HashSet[string]]::new()
            $colList = [System.Collections.Generic.List[string]]::new()
            foreach ($entry in $transformedEntries) {
                foreach ($key in $entry.Keys) {
                    if ($key -ne 'dn' -and $seen.Add($key)) { $colList.Add($key) }
                }
            }
            $columns = $colList.ToArray()
        }
    }

    $currentOutFile = $OutFile
    if ($script:separateOutputFilePerSearch -and $OutFile -and $TotalSearches -gt 1) {
        $ext = [System.IO.Path]::GetExtension($OutFile)
        $base = [System.IO.Path]::ChangeExtension($OutFile, $null).TrimEnd('.')
        $currentOutFile = "${base}-${SearchIndex}${ext}"
    }

    Write-SearchOutput `
        -Entries $transformedEntries `
        -Format $script:outputFormat `
        -Columns $columns `
        -OutFile $currentOutFile `
        -TeeToStdOut:$script:teeResultsToStandardOut `
        -WrapCol $script:wrapColumn `
        -NoWrap:$script:dontWrap `
        -Terse:$script:terse

    if (-not $script:terse -and -not $script:dryRun) {
        Write-Host ""
        Write-Host "# numEntries: $($transformedEntries.Count)" -ForegroundColor DarkGray
    }

    return $transformedEntries.Count
}

# ============================================================================
# Main Execution
# ============================================================================

# Skip the main execution block when dot-sourced (e.g., from the test harness),
# so callers can load helper functions without firing connection/search logic.
if ($MyInvocation.InvocationName -eq '.') {
    return
}

$exitCode = 0

# --- Validate mutually exclusive credential options ---
$credOptionCount = 0
if ($bindPassword) { $credOptionCount++ }
if ($bindPasswordFile) { $credOptionCount++ }
if ($promptForBindPassword) { $credOptionCount++ }
if ($credOptionCount -gt 1) {
    Write-Error "Only one of -bindPassword, -bindPasswordFile, or -promptForBindPassword may be specified."
    exit 1
}

# --- Validate credential completeness ---
if ($credOptionCount -gt 0 -and -not $bindDN) {
    Write-Error "-bindDN is required when using -bindPassword, -bindPasswordFile, or -promptForBindPassword."
    exit 1
}

# --- Validate SSL/TLS options ---
if ($useSSL -and $useStartTLS) {
    Write-Error "-useSSL and -useStartTLS are mutually exclusive. Use one or the other."
    exit 1
}

if ($trustAll -and -not $useSSL -and -not $useStartTLS) {
    Write-Warning "-trustAll has no effect without -useSSL or -useStartTLS."
}

# --- Validate output options ---
if ($teeResultsToStandardOut -and -not $outputFile) {
    Write-Warning "-teeResultsToStandardOut has no effect without -outputFile."
}

if ($separateOutputFilePerSearch -and -not $outputFile) {
    Write-Warning "-separateOutputFilePerSearch has no effect without -outputFile."
}

# --- Resolve hostname ---
if (-not $hostname) {
    try {
        $hostname = ([System.DirectoryServices.ActiveDirectory.Domain]::GetCurrentDomain()).Name
        Write-Verbose "Auto-detected domain: $hostname"
    }
    catch {
        $hostname = 'localhost'
        Write-Verbose "No domain detected, using localhost"
    }
}

# --- Resolve port ---
if ($port -eq 0) {
    if ($useSSL) {
        $port = 636
    }
    else {
        $port = 389
    }
}

# --- Resolve baseDN ---
if (-not $baseDN) {
    try {
        $domainName = ([System.DirectoryServices.ActiveDirectory.Domain]::GetCurrentDomain()).Name
        $baseDN = ($domainName.Split('.') | ForEach-Object { "DC=$_" }) -join ','
        Write-Verbose "Auto-detected base DN: $baseDN"
    }
    catch {
        $baseDN = ''
        Write-Verbose "No domain detected, using empty base DN"
    }
}

# --- Build search specs ---
$searchSpecs = @()

if ($ldapURLFile) {
    $searchSpecs += Read-SearchSpecsFromLdapURLFile -Path $ldapURLFile
}
elseif ($filterFile) {
    $fileFilters = Read-FiltersFromFile -Path $filterFile
    foreach ($ff in $fileFilters) {
        $searchSpecs += @{
            baseDN     = $null
            attributes = $null
            scope      = $null
            filter     = $ff
        }
    }
}

if ($filter) {
    foreach ($f in $filter) {
        if (-not (Test-LdapFilter -Filter $f)) {
            Write-Error "Invalid LDAP filter syntax: $f"
            exit 1
        }
        $searchSpecs += @{
            baseDN     = $null
            attributes = $null
            scope      = $null
            filter     = $f
        }
    }
}

# Default filter if nothing specified
if ($searchSpecs.Count -eq 0) {
    $searchSpecs += @{
        baseDN     = $null
        attributes = $null
        scope      = $null
        filter     = '(objectClass=*)'
    }
}

# --- Validate countEntries with multiple searches ---
if ($countEntries -and $searchSpecs.Count -gt 1) {
    Write-Warning "-countEntries can only be used with a single search. Only the total count will be returned."
}

# --- Scope mapping ---
$scopeMap = @{
    'base'         = [System.DirectoryServices.Protocols.SearchScope]::Base
    'one'          = [System.DirectoryServices.Protocols.SearchScope]::OneLevel
    'sub'          = [System.DirectoryServices.Protocols.SearchScope]::Subtree
    'subordinates' = [System.DirectoryServices.Protocols.SearchScope]::Subtree  # Best approximation
}

# --- Resolve credentials ---
$credential = Get-BindCredential

# --- Connect ---
$connection = $null
try {
    if (-not $dryRun) {
        if (-not $terse) {
            Write-Verbose "Connecting to ${hostname}:${port}..."
        }
        $connection = New-LdapConnection -Server $hostname -ServerPort $port -Credential $credential
        if (-not $terse) {
            Write-Verbose "Connected successfully."
        }
    }
}
catch [System.DirectoryServices.Protocols.LdapException] {
    Write-Error "LDAP connection failed: $($_.Exception.Message) (Error code: $($_.Exception.ErrorCode))"
    exit $_.Exception.ErrorCode
}
catch {
    Write-Error "Connection failed: $($_.Exception.Message)"
    exit 1
}

# --- Execute searches ---
$totalEntryCount = 0
$searchIndex = 0

foreach ($spec in $searchSpecs) {
    $searchIndex++

    # Resolve per-search parameters (URL file can override these)
    $searchBaseDN = if ($spec.baseDN) { $spec.baseDN } else { $baseDN }
    $searchFilter = if ($spec.filter) { $spec.filter } else { '(objectClass=*)' }
    $searchAttrs = if ($spec.attributes) { $spec.attributes } elseif ($requestedAttribute) { $requestedAttribute } else { @() }
    $searchScopeStr = if ($spec.scope) { $spec.scope } else { $scope }
    if (-not $scopeMap.ContainsKey($searchScopeStr)) {
        Write-Error "Invalid scope '$searchScopeStr'. Must be one of: base, one, sub, subordinates."
        if (-not $continueOnError) { break }
        continue
    }
    $searchScope = $scopeMap[$searchScopeStr]

    try {
        $count = Invoke-SearchAndOutput -Conn $connection -BaseDN $searchBaseDN `
            -Filter $searchFilter -Scope $searchScope -Attrs $searchAttrs `
            -SearchIndex $searchIndex -TotalSearches $searchSpecs.Count -OutFile $outputFile
        $totalEntryCount += $count
    }
    catch [System.DirectoryServices.Protocols.LdapException] {
        $ldapEx = $_.Exception
        Write-Error "Search failed: $($ldapEx.Message) (Error code: $($ldapEx.ErrorCode))"

        if ($retryFailedOperations -and $connection) {
            Write-Warning "Retrying with a new connection..."
            try {
                $connection.Dispose()
                $connection = New-LdapConnection -Server $hostname -ServerPort $port -Credential $credential
                $count = Invoke-SearchAndOutput -Conn $connection -BaseDN $searchBaseDN `
                    -Filter $searchFilter -Scope $searchScope -Attrs $searchAttrs `
                    -SearchIndex $searchIndex -TotalSearches $searchSpecs.Count -OutFile $outputFile
                $totalEntryCount += $count
            }
            catch {
                Write-Error "Retry also failed: $($_.Exception.Message)"
                $exitCode = $(if ($_.Exception -is [System.DirectoryServices.Protocols.LdapException]) { $_.Exception.ErrorCode } else { 1 })
                if (-not $continueOnError) { break }
            }
        }
        else {
            $exitCode = $ldapEx.ErrorCode
            if (-not $continueOnError) { break }
        }
    }
    catch [System.DirectoryServices.Protocols.DirectoryOperationException] {
        $opEx = $_.Exception
        $resultCode = $opEx.Response.ResultCode
        Write-Error "Search operation error: $($opEx.Message) (Result: $resultCode)"
        $exitCode = [int]$resultCode
        if (-not $continueOnError) { break }
    }
    catch {
        Write-Error "Unexpected error: $($_.Exception.Message)"
        $exitCode = 1
        if (-not $continueOnError) { break }
    }
}

# --- Cleanup ---
if ($connection) {
    $connection.Dispose()
}

# --- Exit code ---
if ($countEntries) {
    $exitCode = [Math]::Min($totalEntryCount, 255)
}
elseif ($requireMatch -and $totalEntryCount -eq 0 -and $exitCode -eq 0) {
    $exitCode = 1
}

if (-not $terse) {
    Write-Verbose "Total entries returned: $totalEntryCount"
    Write-Verbose "Exit code: $exitCode"
}

exit $exitCode
