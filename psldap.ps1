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
    Note: 'subordinates' is approximated as a subtree search (the .NET
    SearchScope enum has no subordinate-subtree value), so the base entry
    itself is included in results.

.PARAMETER sizeLimit
    Maximum number of entries the server should return. 0 = no limit.

.PARAMETER timeLimitSeconds
    Maximum time in seconds for the server to process each search. 0 = no limit.

.PARAMETER dereferencePolicy
    Alias dereferencing policy: never, always, search, or find. Default: never.

.PARAMETER typesOnly
    Return only attribute names, not values.

.PARAMETER filter
    The LDAP search filter. Pass several as a comma-separated list to run
    several searches: -filter '(cn=a*)','(cn=b*)'. Default: (objectClass=*).

.PARAMETER filterFile
    Path to a file containing LDAP filters (one per line). Lines starting with '#' are ignored.

.PARAMETER ldapURLFile
    Path to a file containing LDAP URLs defining searches. Each URL specifies baseDN,
    scope, filter, and attributes. Host/port in URLs are ignored.

.PARAMETER requestedAttribute
    Attribute(s) to include in results, as a comma-separated list:
    -requestedAttribute cn,mail. '*' (all user attributes) and '+' (all
    operational attributes) are expanded to the attributes actually returned
    in CSV/delimited output.

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
    Exit code represents the number of entries returned (max 255). If any
    search fails, the failure's exit code is returned instead.

.PARAMETER outputFormat
    Output format: LDIF, JSON, CSV, multi-valued-csv, tab-delimited,
    multi-valued-tab-delimited, delimited, multi-valued-delimited,
    dns-only, or values-only. Default: LDIF.

    The 'delimited' / 'multi-valued-delimited' formats emit one header row of
    attribute names followed by one row per entry, with columns joined by the
    -delimiter string. Fields containing the delimiter, a double-quote, or a
    newline are CSV-style quoted, so the result pastes cleanly into Excel.

.PARAMETER delimiter
    Column delimiter for the 'delimited' / 'multi-valued-delimited' output
    formats. Specifying -delimiter is enough to select delimited output:
    when -outputFormat is not given explicitly, -delimiter implies
    'delimited'. Defaults to a TAB when a delimited format is selected
    without -delimiter (TAB is what Excel uses for clipboard paste).
    Common choices: "`t" (tab), "," (comma), "|" (pipe), ";" (semicolon).

.PARAMETER outputFile
    Path to write search results. If not specified, results go to standard output.

.PARAMETER teeResultsToStandardOut
    Write results to both the output file and standard output.

.PARAMETER separateOutputFilePerSearch
    Generate a separate output file per search when using multiple filters.
    Without it, multiple searches share -outputFile: LDIF, dns-only, and
    values-only results are appended in order; JSON and CSV/delimited
    formats require this switch (concatenating them would corrupt the file).

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

.EXAMPLE
    # Tab-delimited columns, ready to paste straight into Excel
    .\psldap.ps1 -filter "(objectClass=user)" -requestedAttribute cn,mail,department -delimiter "`t"

.EXAMPLE
    # Pipe-delimited, collapsing multi-valued attributes into one cell
    .\psldap.ps1 -filter "(objectClass=group)" -requestedAttribute cn,member -outputFormat multi-valued-delimited -delimiter "|"
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
        'multi-valued-tab-delimited', 'delimited', 'multi-valued-delimited',
        'dns-only', 'values-only')]
    [string]$outputFormat = 'LDIF',

    [string]$delimiter,

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
        Returns a NetworkCredential or $null; throws if the resolved
        password is empty. Passwords are handled as
        SecureString throughout and never held in plaintext longer than
        necessary.
    #>
    [SecureString]$securePass = $null

    if ($script:promptForBindPassword) {
        $securePass = Read-Host -Prompt "Enter bind password" -AsSecureString
    }
    elseif ($script:bindPasswordFile) {
        # Build SecureString character-by-character to avoid plaintext string allocation
        $securePass = [System.Security.SecureString]::new()
        $fileBytes = [System.IO.File]::ReadAllBytes($script:bindPasswordFile)
        $fileChars = $null
        try {
            # Honor a byte-order mark. U+FEFF is NOT whitespace, so the trim
            # below would otherwise keep it as the password's first character;
            # and UTF-16 (Windows PowerShell 5.1's default Out-File encoding)
            # decoded as UTF-8 would garble the whole password. No BOM: UTF-8.
            $encoding = [System.Text.Encoding]::UTF8
            $bomLength = 0
            if ($fileBytes.Length -ge 3 -and
                $fileBytes[0] -eq 0xEF -and $fileBytes[1] -eq 0xBB -and $fileBytes[2] -eq 0xBF) {
                $bomLength = 3
            }
            elseif ($fileBytes.Length -ge 2 -and $fileBytes[0] -eq 0xFF -and $fileBytes[1] -eq 0xFE) {
                # Strict decoders (throwOnInvalidBytes): a truncated/odd-length
                # file must fail loudly, not become a U+FFFD in the password.
                $encoding = [System.Text.UnicodeEncoding]::new($false, $false, $true)  # UTF-16LE
                $bomLength = 2
            }
            elseif ($fileBytes.Length -ge 2 -and $fileBytes[0] -eq 0xFE -and $fileBytes[1] -eq 0xFF) {
                $encoding = [System.Text.UnicodeEncoding]::new($true, $false, $true)   # UTF-16BE
                $bomLength = 2
            }
            # Decode first, THEN find the line end: in UTF-16 a CR/LF byte
            # value can appear inside an ordinary character's code unit.
            $fileChars = $encoding.GetChars($fileBytes, $bomLength, $fileBytes.Length - $bomLength)
            $lineEnd = $fileChars.Length
            for ($i = 0; $i -lt $fileChars.Length; $i++) {
                if ($fileChars[$i] -eq "`n" -or $fileChars[$i] -eq "`r") {
                    $lineEnd = $i
                    break
                }
            }
            # Trim leading/trailing whitespace of the first line, append char by char
            $trimStart = 0
            $trimEnd = $lineEnd - 1
            while ($trimStart -le $trimEnd -and [char]::IsWhiteSpace($fileChars[$trimStart])) { $trimStart++ }
            while ($trimEnd -ge $trimStart -and [char]::IsWhiteSpace($fileChars[$trimEnd])) { $trimEnd-- }
            for ($i = $trimStart; $i -le $trimEnd; $i++) {
                $securePass.AppendChar($fileChars[$i])
            }
            $securePass.MakeReadOnly()
        }
        finally {
            # Zero out the byte and char arrays to remove password from memory
            [Array]::Clear($fileBytes, 0, $fileBytes.Length)
            if ($fileChars) { [Array]::Clear($fileChars, 0, $fileChars.Length) }
        }
    }
    elseif ($script:bindPassword) {
        $securePass = $script:bindPassword
    }

    if ($null -ne $securePass) {
        # An empty password with a bind DN is an *unauthenticated* simple bind
        # (RFC 4513 §5.1.2), which some servers accept as anonymous — a
        # silent downgrade. Refuse it instead of sending it.
        if ($securePass.Length -eq 0) {
            throw "The bind password is empty. Supply a non-empty password, or omit -bindDN and the password options to use integrated (Negotiate) auth as the current user."
        }
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
        Checks balanced parentheses, a single top-level filter, and that
        no '(' is immediately followed by '(' or ')'.
    #>
    param([string]$Filter)

    if ([string]::IsNullOrWhiteSpace($Filter)) { return $false }
    if ($Filter[0] -ne '(') { return $false }
    if ($Filter[-1] -ne ')') { return $false }

    $depth = 0
    for ($i = 0; $i -lt $Filter.Length; $i++) {
        $ch = $Filter[$i]
        if ($ch -eq '(') {
            $depth++
            # RFC 4515: '(' must be followed by an operator (&, |, !) or an
            # attribute — so '()' (empty) and '((' (e.g. '((a=b))') are
            # invalid anywhere, top-level or nested. Checked in the same pass.
            if ($i -lt $Filter.Length - 1 -and ($Filter[$i + 1] -eq ')' -or $Filter[$i + 1] -eq '(')) { return $false }
        }
        elseif ($ch -eq ')') { $depth-- }
        if ($depth -lt 0) { return $false }
        # Depth may only return to 0 at the very end — otherwise the string
        # is two sibling filters like '(a=b)(c=d)', not one filter.
        if ($depth -eq 0 -and $i -lt $Filter.Length - 1) { return $false }
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

    $filters = [System.Collections.Generic.List[string]]::new()
    $lineNum = 0
    foreach ($line in (Get-Content -Path $Path)) {
        $lineNum++
        $trimmed = $line.Trim()
        if ($trimmed -and -not $trimmed.StartsWith('#')) {
            if (-not (Test-LdapFilter -Filter $trimmed)) {
                Write-Warning "Skipping invalid filter at line ${lineNum}: $trimmed"
                continue
            }
            $filters.Add($trimmed)
        }
    }
    return $filters.ToArray()
}

function Read-SearchSpecsFromLdapURLFile {
    <#
    .SYNOPSIS
        Parses LDAP URLs from a file and returns search spec hashtables.
        Format: ldap://host:port/baseDN?attributes?scope?filter
    #>
    param([string]$Path)

    $specs = [System.Collections.Generic.List[hashtable]]::new()
    foreach ($line in (Get-Content -Path $Path)) {
        $trimmed = $line.Trim()
        if (-not $trimmed -or $trimmed.StartsWith('#')) { continue }

        # Remove scheme
        $url = $trimmed -replace '^ldaps?://', ''

        # Split host:port from the rest
        $slashIdx = $url.IndexOf('/')
        if ($slashIdx -lt 0) {
            Write-Warning "Skipping LDAP URL with no '/' after host[:port]: $trimmed"
            continue
        }

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
        $specs.Add($spec)
    }
    return $specs.ToArray()
}

function Get-RedactedValues {
    <#
    .SYNOPSIS
        Applies -redactAttribute masking to an attribute's value array.
        Extracted from ConvertTo-TransformedEntry so this logic — which has
        shipped two bugs (a phantom-value fabrication and a lost
        -hideRedactedValueCount guarantee) — is directly unit-testable
        without a SearchResultEntry (which has no public constructor).
    #>
    param(
        [string[]]$Values,
        [switch]$HideCount
    )

    # -hideRedactedValueCount always shows a single marker, even for a
    # zero-value attribute (e.g. under -typesOnly) — that is its documented
    # job ("show only a single '***REDACTED***' regardless of value count").
    if ($HideCount) {
        return @('***REDACTED***')
    }
    if ($Values.Count -eq 1) {
        return @('***REDACTED***')
    }
    if ($Values.Count -gt 1) {
        return @(1..$Values.Count | ForEach-Object { "***REDACTED$_***" })
    }
    # Zero values, no -hideRedactedValueCount: stay empty. `1..0` is a
    # DESCENDING range in PowerShell and would otherwise fabricate two
    # phantom values (***REDACTED1***, ***REDACTED0***).
    return @()
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

    # AttributeNames are the collection's hashtable keys: lowercased, and in
    # an order that changes from run to run (.NET randomizes string hashing
    # per process). Use each attribute's own .Name for the server's casing
    # (givenName, not givenname), sorted so output is stable across runs.
    $attrNames = foreach ($key in $Entry.Attributes.AttributeNames) { $Entry.Attributes[$key].Name }
    $attrNames = @($attrNames | Sort-Object { $_.ToLowerInvariant() })

    foreach ($attrName in $attrNames) {
        $attrNameLower = $attrName.ToLower()

        # Exclude check
        if ($ExcludeAttributes -and ($ExcludeAttributes | Where-Object { $_.ToLower() -eq $attrNameLower })) {
            continue
        }

        $valueList = [System.Collections.Generic.List[string]]::new()
        $attr = $Entry.Attributes[$attrName]
        for ($i = 0; $i -lt $attr.Count; $i++) {
            $val = $attr[$i]
            if ($val -is [byte[]]) {
                $valueList.Add([Convert]::ToBase64String($val))
            }
            else {
                $valueList.Add($val.ToString())
            }
        }
        $values = $valueList.ToArray()

        # Redact check
        if ($RedactAttributes -and ($RedactAttributes | Where-Object { $_.ToLower() -eq $attrNameLower })) {
            $values = Get-RedactedValues -Values $values -HideCount:$HideRedactedCount
        }
        # Scramble check
        elseif ($ScrambleAttributes -and ($ScrambleAttributes | Where-Object { $_.ToLower() -eq $attrNameLower })) {
            # @() keeps a single scrambled value as string[] — a bare pipeline
            # collapses one output to a scalar string, and the CSV/JSON/
            # delimited formatters would then index its first CHARACTER.
            $values = @($values | ForEach-Object { Invoke-ScrambleValue -Value $_ -Seed $ScrambleSeed })
        }

        $result[$attrName] = $values
    }

    return $result
}

function Get-StableStringHash {
    <#
    .SYNOPSIS
        Returns a stable Int32 hash of a string. Used instead of String.GetHashCode()
        because that is randomized per-process on .NET Core / PowerShell 7+,
        which would break cross-run determinism of scrambled values.

        Uses SHA256 (non-cryptographic use here — just a stable mixer; only the
        first 4 bytes of the digest are kept and interpreted as a signed Int32).
        Calls the static [SHA256]::HashData(byte[]) method (.NET 5+ /
        PowerShell 7.2+), so there is no instance to allocate, no IDisposable
        to track, and the call is inherently thread-safe.

        Implements Option B from issue #15. Requires PowerShell 7.2+.
    #>
    param([string]$Value)

    if ([string]::IsNullOrEmpty($Value)) { return 0 }

    $bytes = [System.Text.Encoding]::UTF8.GetBytes($Value)
    $hashBytes = [System.Security.Cryptography.SHA256]::HashData($bytes)
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
            # An attribute with no values (e.g. under -typesOnly) is still
            # listed, as a bare 'name:' line — matching ldapsearch -A —
            # instead of vanishing so that only the dn: line is printed.
            if (@($entry[$key]).Count -eq 0) {
                [void]$sb.AppendLine("${key}:")
                continue
            }
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

    $objects = [System.Collections.Generic.List[PSCustomObject]]::new()
    foreach ($entry in $Entries) {
        $obj = [ordered]@{ dn = $entry.dn }
        foreach ($key in $entry.Keys) {
            if ($key -eq 'dn') { continue }
            # @() so a scalar value (e.g. a plain string) is treated as one
            # value, not indexed by character below.
            $vals = @($entry[$key])
            if ($vals.Count -eq 1) {
                $obj[$key] = $vals[0]
            }
            else {
                $obj[$key] = $vals
            }
        }
        $objects.Add([PSCustomObject]$obj)
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
        Formats entries as CSV or multi-valued CSV. Thin wrapper over
        Format-DelimitedOutput with a comma delimiter (mirrors Format-TabOutput).
    #>
    param(
        [array]$Entries,
        [string[]]$Columns,
        [switch]$MultiValued
    )

    return Format-DelimitedOutput -Entries $Entries -Columns $Columns -Delimiter ',' -MultiValued:$MultiValued
}

function Format-CsvField {
    <#
    .SYNOPSIS
        Properly escapes a CSV field value. Thin wrapper over
        Format-DelimitedField with a comma delimiter.
    #>
    param([string]$Value)

    return Format-DelimitedField -Value $Value -Delimiter ','
}

function Format-DelimitedField {
    <#
    .SYNOPSIS
        Escapes a single field for delimited output. Quotes (CSV-style, with
        doubled inner quotes) when the value contains the delimiter, a
        double-quote, or a line break — so the row stays aligned and pastes
        cleanly into Excel regardless of which delimiter was chosen.
    #>
    param(
        [string]$Value,
        [string]$Delimiter
    )

    if ([string]::IsNullOrEmpty($Value)) { return '' }
    if ($Value.Contains($Delimiter) -or $Value -match '["\r\n]') {
        return '"' + ($Value -replace '"', '""') + '"'
    }
    return $Value
}

function Format-DelimitedOutput {
    <#
    .SYNOPSIS
        Formats entries as delimiter-separated columns: one header row of
        attribute names, then one row per entry. Used by the tab-delimited and
        the generic 'delimited' output formats.
    #>
    param(
        [array]$Entries,
        [string[]]$Columns,
        [string]$Delimiter = "`t",
        [switch]$MultiValued
    )

    $sb = [System.Text.StringBuilder]::new()

    # Header
    [void]$sb.AppendLine((($Columns | ForEach-Object { Format-DelimitedField -Value $_ -Delimiter $Delimiter }) -join $Delimiter))

    foreach ($entry in $Entries) {
        $row = @()
        foreach ($col in $Columns) {
            # @() so a scalar value is one field, not indexed by character.
            $vals = @($entry[$col])
            if (-not $vals) {
                $row += ''
            }
            elseif ($MultiValued) {
                $row += Format-DelimitedField -Value (($vals) -join '|') -Delimiter $Delimiter
            }
            else {
                $row += Format-DelimitedField -Value ($vals[0]) -Delimiter $Delimiter
            }
        }
        [void]$sb.AppendLine($row -join $Delimiter)
    }

    return $sb.ToString()
}

function Format-TabOutput {
    <#
    .SYNOPSIS
        Formats entries as tab-delimited output. Thin wrapper over
        Format-DelimitedOutput with a TAB delimiter.
    #>
    param(
        [array]$Entries,
        [string[]]$Columns,
        [switch]$MultiValued
    )

    return Format-DelimitedOutput -Entries $Entries -Columns $Columns -Delimiter "`t" -MultiValued:$MultiValued
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
        [string]$Delimiter = "`t",
        [string]$OutFile,
        [switch]$TeeToStdOut,
        [int]$WrapCol,
        [switch]$NoWrap,
        [switch]$Terse,
        [switch]$Append
    )

    $output = switch ($Format) {
        # When appending a later search to an LDIF file, skip the
        # 'version: 1' header: RFC 2849 allows it only at the start.
        'LDIF' { Format-LdifOutput -Entries $Entries -WrapCol $WrapCol -NoWrap:$NoWrap -Terse:($Terse -or $Append) }
        'JSON' { Format-JsonOutput -Entries $Entries }
        'CSV' { Format-CsvOutput -Entries $Entries -Columns $Columns }
        'multi-valued-csv' { Format-CsvOutput -Entries $Entries -Columns $Columns -MultiValued }
        'tab-delimited' { Format-TabOutput -Entries $Entries -Columns $Columns }
        'multi-valued-tab-delimited' { Format-TabOutput -Entries $Entries -Columns $Columns -MultiValued }
        'delimited' { Format-DelimitedOutput -Entries $Entries -Columns $Columns -Delimiter $Delimiter }
        'multi-valued-delimited' { Format-DelimitedOutput -Entries $Entries -Columns $Columns -Delimiter $Delimiter -MultiValued }
        'dns-only' { Format-DnsOnlyOutput -Entries $Entries }
        'values-only' { Format-ValuesOnlyOutput -Entries $Entries }
    }

    if ($OutFile) {
        # UTF-8 without BOM. Out-File -Encoding UTF8 writes a BOM on Windows PowerShell 5.1,
        # which breaks LDIF (RFC 2849 mandates no BOM) and many CSV consumers.
        $resolvedPath = $ExecutionContext.SessionState.Path.GetUnresolvedProviderPathFromPSPath($OutFile)
        $utf8NoBom = [System.Text.UTF8Encoding]::new($false)
        if ($Append) {
            [System.IO.File]::AppendAllText($resolvedPath, $output, $utf8NoBom)
        }
        else {
            [System.IO.File]::WriteAllText($resolvedPath, $output, $utf8NoBom)
        }
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

function ConvertTo-DereferenceAlias {
    <#
    .SYNOPSIS
        Maps a -dereferencePolicy name (never/always/search/find) to the
        DereferenceAlias enum. The .NET member names are Never, Always,
        InSearching and FindingBaseObject — NOT the C-API-style
        NeverDerefAliases / DerefAlways / ...: those don't exist, evaluate to
        $null in PowerShell, and made setting SearchRequest.Aliases throw on
        every real search (the default policy is 'never').
    #>
    param([string]$Policy)

    switch ($Policy) {
        'never'  { return [System.DirectoryServices.Protocols.DereferenceAlias]::Never }
        'always' { return [System.DirectoryServices.Protocols.DereferenceAlias]::Always }
        'search' { return [System.DirectoryServices.Protocols.DereferenceAlias]::InSearching }
        'find'   { return [System.DirectoryServices.Protocols.DereferenceAlias]::FindingBaseObject }
        default  { throw "Invalid dereference policy '$Policy'. Must be one of: never, always, search, find." }
    }
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
        $request.Aliases = ConvertTo-DereferenceAlias -Policy $DerefPolicy
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

        try {
            $response = $Connection.SendRequest($request)
        }
        catch [System.DirectoryServices.Protocols.DirectoryOperationException] {
            # A server-enforced size or time limit surfaces as a thrown
            # exception with the partial results attached to its Response.
            # Stash them on the exception's Data dictionary (like ldapsearch,
            # keep what was received) and re-throw unchanged: the search is
            # still a failure — Invoke-SearchAndOutput writes the partial
            # entries, then the caller's usual exit-code / -continueOnError
            # handling still applies, matching every other search error.
            $errResponse = $_.Exception.Response
            $resultCode = $errResponse.ResultCode
            if ($errResponse -is [System.DirectoryServices.Protocols.SearchResponse] -and
                ($resultCode -eq [System.DirectoryServices.Protocols.ResultCode]::SizeLimitExceeded -or
                 $resultCode -eq [System.DirectoryServices.Protocols.ResultCode]::TimeLimitExceeded)) {
                foreach ($entry in $errResponse.Entries) {
                    $allEntries.Add($entry)
                }
                $_.Exception.Data['PartialEntries'] = $allEntries
            }
            throw
        }

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

    # The loop appends whole pages, so the last page can overshoot the
    # requested size limit — trim to exactly MaxResults.
    if ($MaxResults -gt 0 -and $allEntries.Count -gt $MaxResults) {
        $allEntries = $allEntries.GetRange(0, $MaxResults)
    }

    return $allEntries
}

function Get-OutputColumns {
    <#
    .SYNOPSIS
        Chooses the column list for CSV / tab / delimited output.
        Explicitly requested attributes are used as-is. '*' (all user
        attributes) and '+' (all operational attributes) are request
        wildcards, not attribute names — they never appear as entry keys, so
        as literal columns they'd be blank. With a wildcard (or no attributes
        requested), the columns are the named attributes first, then every
        other attribute found in the entries, in first-seen order.
    #>
    param(
        [string[]]$Attrs,
        [array]$Entries
    )

    $namedAttrs = @($Attrs | Where-Object { $_ -and $_ -ne '*' -and $_ -ne '+' })
    if ($Attrs.Count -gt 0 -and $namedAttrs.Count -eq $Attrs.Count) {
        return $Attrs
    }

    # Insertion-ordered de-duplication (no LinkedHashSet in .NET).
    $seen = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)
    $colList = [System.Collections.Generic.List[string]]::new()
    foreach ($name in $namedAttrs) {
        if ($name -ne 'dn' -and $seen.Add($name)) { $colList.Add($name) }
    }
    foreach ($entry in $Entries) {
        foreach ($key in $entry.Keys) {
            if ($key -ne 'dn' -and $seen.Add($key)) { $colList.Add($key) }
        }
    }
    return $colList.ToArray()
}

function Invoke-SearchAndOutput {
    <#
    .SYNOPSIS
        Executes a single search, transforms entries, and writes output.
        The entry count is reported through -EntryCount ([ref]), NOT the
        return value: when output goes to stdout, Write-SearchOutput emits
        the formatted text on this function's success stream, so a returned
        count would be mixed in with it. If the server truncates the
        search (SizeLimitExceeded/TimeLimitExceeded), the partial entries
        it returned are still transformed and written, then the failure is
        re-thrown so the caller's usual exit-code / -continueOnError
        handling still applies to this search.
    #>
    param(
        [System.DirectoryServices.Protocols.LdapConnection]$Conn,
        [string]$BaseDN,
        [string]$Filter,
        [System.DirectoryServices.Protocols.SearchScope]$Scope,
        [string[]]$Attrs,
        [int]$SearchIndex,
        [int]$TotalSearches,
        [string]$OutFile,
        [ref]$EntryCount
    )

    $searchFailure = $null
    try {
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
    }
    catch [System.DirectoryServices.Protocols.DirectoryOperationException] {
        if (-not $_.Exception.Data.Contains('PartialEntries')) { throw }
        $rawEntries = $_.Exception.Data['PartialEntries']
        $searchFailure = $_.Exception
        Write-Warning "Writing the $($rawEntries.Count) entries received before reporting the failure."
    }

    $transformedEntries = [System.Collections.Generic.List[object]]::new()
    foreach ($rawEntry in $rawEntries) {
        $transformedEntries.Add((ConvertTo-TransformedEntry `
            -Entry $rawEntry `
            -ExcludeAttributes $script:excludeAttribute `
            -RedactAttributes $script:redactAttribute `
            -HideRedactedCount:$script:hideRedactedValueCount `
            -ScrambleAttributes $script:scrambleAttribute `
            -ScrambleSeed $script:scrambleRandomSeed))
    }

    $columns = @()
    if ($script:outputFormat -in @('CSV', 'multi-valued-csv', 'tab-delimited', 'multi-valued-tab-delimited', 'delimited', 'multi-valued-delimited')) {
        $columns = @(Get-OutputColumns -Attrs $Attrs -Entries $transformedEntries)
    }

    $currentOutFile = $OutFile
    $appendToFile = $false
    if ($script:separateOutputFilePerSearch -and $OutFile -and $TotalSearches -gt 1) {
        $ext = [System.IO.Path]::GetExtension($OutFile)
        $base = [System.IO.Path]::ChangeExtension($OutFile, $null).TrimEnd('.')
        $currentOutFile = "${base}-${SearchIndex}${ext}"
    }
    elseif ($OutFile) {
        # Several searches sharing one file: the first write of this run
        # truncates it, later searches append rather than overwrite. Keyed on
        # the path and search index, so a first search (or a different file,
        # e.g. when dot-sourced) never appends to a stale file.
        $appendToFile = ($SearchIndex -gt 1 -and $script:sharedOutputFilePath -eq $OutFile)
        $script:sharedOutputFilePath = $OutFile
    }

    Write-SearchOutput `
        -Entries $transformedEntries `
        -Format $script:outputFormat `
        -Columns $columns `
        -Delimiter $script:delimiter `
        -OutFile $currentOutFile `
        -TeeToStdOut:$script:teeResultsToStandardOut `
        -WrapCol $script:wrapColumn `
        -NoWrap:$script:dontWrap `
        -Terse:$script:terse `
        -Append:$appendToFile

    if (-not $script:terse -and -not $script:dryRun) {
        Write-Host ""
        Write-Host "# numEntries: $($transformedEntries.Count)" -ForegroundColor DarkGray
    }

    if ($EntryCount) { $EntryCount.Value = $transformedEntries.Count }

    if ($searchFailure) {
        # Partial results are already written (and counted) above; now
        # surface the original failure so it still counts as a failed search.
        throw $searchFailure
    }
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

if ($bindDN -and $credOptionCount -eq 0) {
    Write-Warning ("-bindDN was specified without a password option and will be IGNORED. " +
        "The bind will use integrated (Negotiate) auth as the current user. " +
        "Add -promptForBindPassword, -bindPassword, or -bindPasswordFile to bind as '$bindDN'.")
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

# --- Resolve delimited output options ---
# Specifying -delimiter is enough to select delimited output: when the caller
# didn't pass an explicit -outputFormat, -delimiter implies 'delimited'.
if ($PSBoundParameters.ContainsKey('delimiter') -and -not $PSBoundParameters.ContainsKey('outputFormat')) {
    $outputFormat = 'delimited'
}

if ($outputFormat -in @('delimited', 'multi-valued-delimited')) {
    if ($PSBoundParameters.ContainsKey('delimiter')) {
        if ([string]::IsNullOrEmpty($delimiter)) {
            Write-Error "-delimiter cannot be empty."
            exit 1
        }
    }
    else {
        # No delimiter given for a delimited format: default to TAB, which is
        # the column separator Excel expects on a clipboard paste.
        $delimiter = "`t"
    }
}
elseif ($PSBoundParameters.ContainsKey('delimiter')) {
    Write-Warning "-delimiter has no effect with -outputFormat '$outputFormat'."
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
$searchSpecs = [System.Collections.Generic.List[hashtable]]::new()

if ($ldapURLFile) {
    foreach ($s in (Read-SearchSpecsFromLdapURLFile -Path $ldapURLFile)) { $searchSpecs.Add($s) }
}
elseif ($filterFile) {
    foreach ($ff in (Read-FiltersFromFile -Path $filterFile)) {
        $searchSpecs.Add(@{
            baseDN     = $null
            attributes = $null
            scope      = $null
            filter     = $ff
        })
    }
}

# A file that yields no searches (every line invalid, or only comments) is
# an error — NOT a cue to fall through to the '(objectClass=*)' default below,
# which would silently dump the whole directory instead of what was asked.
if (($ldapURLFile -or $filterFile) -and $searchSpecs.Count -eq 0) {
    $sourceFile = $(if ($ldapURLFile) { $ldapURLFile } else { $filterFile })
    Write-Error "No valid searches found in '$sourceFile'."
    exit 1
}

if ($filter) {
    foreach ($f in $filter) {
        if (-not (Test-LdapFilter -Filter $f)) {
            Write-Error "Invalid LDAP filter syntax: $f"
            exit 1
        }
        $searchSpecs.Add(@{
            baseDN     = $null
            attributes = $null
            scope      = $null
            filter     = $f
        })
    }
}

# Default filter if nothing specified
if ($searchSpecs.Count -eq 0) {
    $searchSpecs.Add(@{
        baseDN     = $null
        attributes = $null
        scope      = $null
        filter     = '(objectClass=*)'
    })
}

# --- Validate multiple searches sharing one output file ---
# LDIF, dns-only, and values-only concatenate cleanly, so later searches are
# appended. JSON and CSV/delimited do not: a second JSON array or a second
# header row would corrupt the file, so require one file per search.
$script:sharedOutputFilePath = $null
if ($outputFile -and -not $separateOutputFilePerSearch -and $searchSpecs.Count -gt 1 -and
    $outputFormat -notin @('LDIF', 'dns-only', 'values-only')) {
    Write-Error ("$($searchSpecs.Count) searches cannot share one -outputFile with -outputFormat '$outputFormat'. " +
        "Add -separateOutputFilePerSearch, or use LDIF, dns-only, or values-only.")
    exit 1
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
try {
    $credential = Get-BindCredential
}
catch {
    Write-Error "Could not read bind credentials: $($_.Exception.Message)"
    exit 1
}

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
        $exitCode = 1
        if (-not $continueOnError) { break }
        continue
    }
    $searchScope = $scopeMap[$searchScopeStr]

    # The count comes back through [ref]: the function's success stream is
    # the formatted output itself, which must flow through to stdout.
    $searchCount = 0
    try {
        Invoke-SearchAndOutput -Conn $connection -BaseDN $searchBaseDN `
            -Filter $searchFilter -Scope $searchScope -Attrs $searchAttrs `
            -SearchIndex $searchIndex -TotalSearches $searchSpecs.Count -OutFile $outputFile `
            -EntryCount ([ref]$searchCount)
    }
    catch [System.DirectoryServices.Protocols.LdapException] {
        $ldapEx = $_.Exception
        Write-Error "Search failed: $($ldapEx.Message) (Error code: $($ldapEx.ErrorCode))"

        if ($retryFailedOperations -and $connection) {
            Write-Warning "Retrying with a new connection..."
            try {
                $connection.Dispose()
                $connection = New-LdapConnection -Server $hostname -ServerPort $port -Credential $credential
                Invoke-SearchAndOutput -Conn $connection -BaseDN $searchBaseDN `
                    -Filter $searchFilter -Scope $searchScope -Attrs $searchAttrs `
                    -SearchIndex $searchIndex -TotalSearches $searchSpecs.Count -OutFile $outputFile `
                    -EntryCount ([ref]$searchCount)
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
    finally {
        # Runs even when a catch above breaks out of the loop, so entries
        # written from a partial (size/time-limited) search are counted too.
        $totalEntryCount += $searchCount
    }
}

# --- Cleanup ---
if ($connection) {
    $connection.Dispose()
}

# --- Exit code ---
# A failure always wins: -countEntries reports the count only when every
# search succeeded, otherwise a failed run could exit 0 (or with a count
# that looks like a success) and hide the error from automation.
if ($countEntries -and $exitCode -eq 0) {
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
