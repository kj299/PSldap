<#
.SYNOPSIS
    Lightweight, native-only AD LDAP query script. No PowerShell modules
    required, no RSAT dependency.

.DESCRIPTION
    Defines Invoke-AdLdapQuery, a function that runs a single LDAP search
    against the current user's domain using only .NET BCL classes that
    ship with every Windows install:

      - System.DirectoryServices.ActiveDirectory.Domain (domain discovery)
      - System.DirectoryServices.DirectoryEntry        (LDAP bind)
      - System.DirectoryServices.DirectorySearcher     (paged search)

    Authentication uses Kerberos / GSSAPI implicitly via the calling
    user's logon token. There is no plaintext password handling.

    The script can be either dot-sourced (so the test harness can call
    the function in-process) or invoked directly with -Filter for a
    one-shot query.

.PARAMETER Filter
    Required. The LDAP filter, e.g. "(objectClass=user)". Validated for
    parenthesis balance before any AD I/O happens, so malformed filters
    fail fast and locally without a server round-trip.

.PARAMETER Properties
    Optional. Attributes to load. Defaults to a small set of the most
    common user/object attributes:
      samAccountName, displayName, mail, distinguishedName,
      objectClass, userPrincipalName

.PARAMETER MaxResults
    Optional. Server-side size limit. Defaults to 100. Capped at 1000
    per page (DirectorySearcher PageSize).

.EXAMPLE
    .\Invoke-AdLdapQuery.ps1 -Filter '(objectClass=user)' -MaxResults 5

.EXAMPLE
    . .\Invoke-AdLdapQuery.ps1
    Invoke-AdLdapQuery -Filter '(samAccountName=jdoe)' -Properties mail,displayName

.NOTES
    No [CmdletBinding()] is used; the script-level param() block is
    intentionally non-mandatory so dot-sourcing for tests does not
    prompt for input.

    Why DirectorySearcher instead of the ActiveDirectory module?
      - The AD module ships with RSAT and is not installed on locked-
        down or non-admin workstations.
      - DirectorySearcher / DirectoryEntry are part of the .NET BCL on
        every Windows PowerShell install.
      - No external module install, no admin rights, no DSC bootstrap.
#>

param(
    [string]$Filter,
    [string[]]$Properties,
    [int]$MaxResults = 100
)

# ============================================================================
# Helper: structural LDAP-filter check (no AD round-trip).
# Catches the most common malformed filters (unbalanced parens, empty input)
# locally so the function fails fast without binding to AD.
# ============================================================================
function Test-AdLdapFilterShape {
    param([string]$Value)

    if ([string]::IsNullOrWhiteSpace($Value)) { return $false }
    if ($Value[0] -ne '(' -or $Value[$Value.Length - 1] -ne ')') { return $false }

    $depth = 0
    foreach ($ch in $Value.ToCharArray()) {
        if ($ch -eq '(') { $depth++ }
        elseif ($ch -eq ')') { $depth-- }
        if ($depth -lt 0) { return $false }
    }
    return ($depth -eq 0)
}

# ============================================================================
# Helper: discover the current AD domain via .NET (no RSAT, no modules).
# Returns the FQDN string, or throws with a clear message.
# ============================================================================
function Get-AdLdapCurrentDomain {
    try {
        $d = [System.DirectoryServices.ActiveDirectory.Domain]::GetCurrentDomain()
        return $d.Name
    }
    catch {
        throw "Could not discover the current Active Directory domain. " +
              "Is this machine domain-joined and reachable? " +
              "Inner: $($_.Exception.Message)"
    }
}

# ============================================================================
# The main exported function.
# ============================================================================
function Invoke-AdLdapQuery {
    param(
        [string]$Filter,
        [string[]]$Properties = @(
            'samAccountName',
            'displayName',
            'mail',
            'distinguishedName',
            'objectClass',
            'userPrincipalName'
        ),
        [int]$MaxResults = 100
    )

    # --- Local validation (no AD I/O yet) ---
    if (-not (Test-AdLdapFilterShape -Value $Filter)) {
        throw "Invalid LDAP filter: '$Filter'. " +
              "Filter must be non-empty, start with '(', end with ')', " +
              "and have balanced parentheses."
    }

    if ($MaxResults -lt 1) {
        throw "MaxResults must be a positive integer (got $MaxResults)."
    }

    # --- Domain discovery ---
    $domainName = Get-AdLdapCurrentDomain
    $rootPath = "LDAP://$domainName"

    # --- Bind ---
    # No credentials passed = bind as the current logged-on user via Kerberos.
    # No plaintext password ever leaves this process.
    $root = $null
    $searcher = $null
    $results = $null
    try {
        try {
            $root = New-Object System.DirectoryServices.DirectoryEntry $rootPath
            # Force-touch a property so a bind error (Kerberos failure, etc.)
            # surfaces here rather than later inside FindAll().
            $null = $root.Name
        }
        catch {
            throw "Failed to bind to '$rootPath' as the current user. " +
                  "Possible Kerberos / domain reachability issue. " +
                  "Inner: $($_.Exception.Message)"
        }

        # --- Search ---
        try {
            $searcher = New-Object System.DirectoryServices.DirectorySearcher $root
            $searcher.Filter = $Filter
            $searcher.SizeLimit = $MaxResults
            # PageSize > 0 enables paged results; cap at 1000 per RFC convention.
            $pageSize = [Math]::Min(1000, [Math]::Max(1, $MaxResults))
            $searcher.PageSize = $pageSize
            $searcher.SearchScope = [System.DirectoryServices.SearchScope]::Subtree

            foreach ($prop in $Properties) {
                if (-not [string]::IsNullOrWhiteSpace($prop)) {
                    [void]$searcher.PropertiesToLoad.Add($prop)
                }
            }

            $results = $searcher.FindAll()
        }
        catch [System.Runtime.InteropServices.COMException] {
            # COM 0x80072020 / 0x8007203E etc. usually means a server-side
            # filter parse error or operations error.
            throw "LDAP search failed (server rejected the request). " +
                  "Filter: '$Filter'. Inner: $($_.Exception.Message)"
        }
        catch {
            throw "LDAP search failed. Filter: '$Filter'. Inner: $($_.Exception.Message)"
        }

        # --- Project results into PSCustomObjects ---
        foreach ($result in $results) {
            $obj = [ordered]@{}
            foreach ($prop in $Properties) {
                $vals = $result.Properties[$prop]
                if ($vals -and $vals.Count -gt 0) {
                    if ($vals.Count -eq 1) {
                        $obj[$prop] = $vals[0]
                    }
                    else {
                        $obj[$prop] = @($vals)
                    }
                }
                else {
                    $obj[$prop] = $null
                }
            }
            [PSCustomObject]$obj
        }
    }
    finally {
        if ($results)  { try { $results.Dispose() }  catch {} }
        if ($searcher) { try { $searcher.Dispose() } catch {} }
        if ($root)     { try { $root.Dispose() }     catch {} }
    }
}

# ============================================================================
# Standalone-invocation entry point.
# When the file is dot-sourced ($MyInvocation.InvocationName -eq '.'), do
# nothing — let the caller use Invoke-AdLdapQuery directly.
# When invoked as a script with -Filter, forward to the function.
# ============================================================================
if ($MyInvocation.InvocationName -ne '.' -and $Filter) {
    $callArgs = @{ Filter = $Filter }
    if ($PSBoundParameters.ContainsKey('Properties')) { $callArgs.Properties = $Properties }
    if ($PSBoundParameters.ContainsKey('MaxResults')) { $callArgs.MaxResults = $MaxResults }
    Invoke-AdLdapQuery @callArgs
}
