<#
.SYNOPSIS
    This script provides functions to connect to and query LDAP servers.

.DESCRIPTION
    The script contains functions to connect to LDAP servers, perform searches, and process the results.
    It supports both secure (LDAPS) and non-secure (LDAP) connections and allows for paging of large result sets.
    Credentials can be provided to authenticate with the LDAP server.

.NOTES
    Author: Your Name
    Version: 1.0
    Last Updated: 2023-04-22

#>

function Connect-LDAPServer {
    <#
    .SYNOPSIS
        Connects to an LDAP server.

    .DESCRIPTION
        This function establishes a connection to an LDAP server using the provided parameters.
        It supports both secure (LDAPS) and non-secure (LDAP) connections.

    .PARAMETER LDAPServer
        The LDAP server to connect to.

    .PARAMETER Port
        The port number to use for the LDAP connection. Default is 389 for non-secure connections and 636 for secure connections.

    .PARAMETER Credential
        The credentials to use for authentication with the LDAP server.

    .PARAMETER Secure
        Switch to indicate if a secure (LDAPS) connection should be used.

    .EXAMPLE
        Connect-LDAPServer -LDAPServer 'ldap.example.com' -Credential (Get-Credential)

        Connects to the LDAP server 'ldap.example.com' using the provided credentials over a non-secure connection.

    .EXAMPLE
        Connect-LDAPServer -LDAPServer 'ldaps.example.com' -Secure -Credential $credObject

        Connects to the LDAP server 'ldaps.example.com' using the provided credential object over a secure connection.
    #>

    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true)]
        [string]$LDAPServer,

        [Parameter(Mandatory = $false)]
        [int]$Port,

        [Parameter(Mandatory = $true)]
        [pscredential]$Credential,

        [Parameter(Mandatory = $false)]
        [switch]$Secure
    )

    # Set the default port if not provided
    if (-not $Port) {
        $Port = if ($Secure) { 636 } else { 389 }
    }

    # Set the authentication type based on the secure flag
    $authType = if ($Secure) {
        [System.DirectoryServices.AuthenticationTypes]::SecureSocketsLayer
    } else {
        [System.DirectoryServices.AuthenticationTypes]::ServerBind
    }

    # Create the LDAP connection
    $ldapConnection = New-Object System.DirectoryServices.Protocols.LDAPConnection("$($LDAPServer):$Port", $Credential.GetNetworkCredential())
    $ldapConnection.AuthType = $authType

    return $ldapConnection
}

function Search-LDAP {
    <#
    .SYNOPSIS
        Performs a search on an LDAP server.

    .DESCRIPTION
        This function executes a search query on an LDAP server using the provided parameters.
        It supports paging of large result sets and allows customization of search scope, filter, and attributes.

    .PARAMETER LDAPConnection
        The LDAP connection object obtained from the Connect-LDAPServer function.

    .PARAMETER BaseDN
        The base distinguished name (DN) for the search.

    .PARAMETER Filter
        The LDAP filter to use for the search.

    .PARAMETER Scope
        The search scope to use (Base, OneLevel, or Subtree).

    .PARAMETER Attributes
        The attributes to retrieve for each search result.

    .PARAMETER PageSize
        The page size for paging large result sets.

    .EXAMPLE
        $ldapConn = Connect-LDAPServer -LDAPServer 'ldap.example.com' -Credential (Get-Credential)
        Search-LDAP -LDAPConnection $ldapConn -BaseDN 'DC=example,DC=com' -Filter '(objectClass=user)' -Attributes 'sAMAccountName', 'displayName', 'mail'

        Performs a search on the LDAP server 'ldap.example.com' with the base DN 'DC=example,DC=com', filter '(objectClass=user)', and retrieves the 'sAMAccountName', 'displayName', and 'mail' attributes for each result.

    .EXAMPLE
        Search-LDAP -LDAPConnection $ldapConn -BaseDN 'OU=Users,DC=example,DC=com' -Filter '(&(objectClass=user)(mail=*@example.com))' -Scope OneLevel -Attributes 'sAMAccountName', 'displayName', 'mail' -PageSize 1000

        Performs a search on the LDAP server with the base DN 'OU=Users,DC=example,DC=com', filter '(&(objectClass=user)(mail=*@example.com))', search scope 'OneLevel', retrieves the 'sAMAccountName', 'displayName', and 'mail' attributes, and uses a page size of 1000 for paging large result sets.
    #>

    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true)]
        [System.DirectoryServices.Protocols.LDAPConnection]$LDAPConnection,

        [Parameter(Mandatory = $true)]
        [string]$BaseDN,

        [Parameter(Mandatory = $true)]
        [string]$Filter,

        [Parameter(Mandatory = $false)]
        [ValidateSet('Base', 'OneLevel', 'Subtree')]
        [string]$Scope = 'Subtree',

        [Parameter(Mandatory = $true)]
        [string[]]$Attributes,

        [Parameter(Mandatory = $false)]
        [int]$PageSize = 1000
    )

    # Create a DirectoryEntry from the LDAPConnection
    $directoryEntry = New-Object System.DirectoryServices.DirectoryEntry("LDAP://$($LDAPConnection.SessionOptions.HostName)/$BaseDN", $LDAPConnection.Credential)

    # Create the searcher
    $searcher = New-Object System.DirectoryServices.DirectorySearcher($directoryEntry)
    $searcher.Filter = $Filter
    $searcher.SearchScope = $Scope
    $searcher.PropertiesToLoad.AddRange($Attributes)
    $searcher.PageSize = $PageSize

    try {
        # Perform the search and process the results
        $results = $searcher.FindAll()
        $results | ForEach-Object {
            $result = @{}
            $_.Properties.PropertyNames | ForEach-Object {
                $result[$_] = $_.Properties[$_]
            }
            [PSCustomObject]$result
        }
    }
    catch {
        Write-Error "An error occurred during the LDAP search: $_"
    }
    finally {
        # Dispose of the DirectoryEntry and LDAPConnection
        $directoryEntry.Dispose()
        $LDAPConnection.Dispose()
    }
}