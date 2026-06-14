# PSldap

A PowerShell implementation inspired by the `ldapsearch` command-line tool.
Query any LDAP directory server using custom filters, scopes, and attribute
selections — with SSL/TLS, StartTLS, paged results, server-side sorting,
multiple output formats, and value transformations (exclude / redact /
scramble).

## Requirements

- Windows PowerShell **5.1** (or PowerShell 7+).
- **No PowerShell modules to install.** The script uses only .NET BCL
  assemblies that ship with Windows
  (`System.DirectoryServices.Protocols`, `System.Net`).

## Installation

Download or clone the repository — there is no install step.

```
git clone https://github.com/kj299/PSldap.git
```

Or just copy [psldap.ps1](psldap.ps1) anywhere on disk.

## Quick start

```powershell
# Anonymous bind, default filter, auto-detect domain & baseDN
.\psldap.ps1

# Specific server, filter, and attributes
.\psldap.ps1 -hostname ldap.example.com `
             -baseDN "dc=example,dc=com" `
             -filter "(objectClass=user)" `
             -requestedAttribute cn,mail

# LDAPS with credentials, prompted for password
.\psldap.ps1 -hostname ldap.example.com -port 636 -useSSL -trustAll `
             -bindDN "cn=admin,dc=example,dc=com" -promptForBindPassword `
             -baseDN "dc=example,dc=com" -filter "(uid=jdoe)" `
             -outputFormat JSON

# Read filters from a file, write CSV
.\psldap.ps1 -filterFile .\filters.txt `
             -baseDN "dc=example,dc=com" `
             -outputFormat CSV `
             -requestedAttribute cn,mail,telephoneNumber `
             -outputFile results.csv

# Multiple searches via LDAP-URL file
.\psldap.ps1 -ldapURLFile .\urls.txt -outputFormat LDIF -continueOnError
```

Run `Get-Help .\psldap.ps1 -Detailed` for the full parameter reference.

## Authentication

By default — when no `-bindDN` / password is supplied — the script binds with
**`AuthType::Negotiate` using the current Windows logon**. That means it queries
Active Directory with the calling user's own credentials (Kerberos/NTLM via
SSPI), exactly like the logged-on user. No password is prompted for, stored, or
sent in plaintext, and no module or RSAT install is required.

```powershell
# Query the current user's domain with their own credentials (integrated auth)
.\psldap.ps1 -hostname dc01.example.com `
             -baseDN "dc=example,dc=com" `
             -filter "(samAccountName=jdoe)"
```

Supplying `-bindDN` together with a password option (`-promptForBindPassword`,
`-bindPassword`, or `-bindPasswordFile`) switches to explicit `Basic` auth with
those credentials instead.

> This integrated path targets on-premises Active Directory (and LDAP-enabled
> managed domains / hybrid-synced environments). Cloud-only Microsoft Entra ID
> has no LDAP endpoint and is not reachable this way.

## Output formats

`LDIF` (default), `JSON`, `CSV`, `multi-valued-csv`, `tab-delimited`,
`multi-valued-tab-delimited`, `delimited`, `multi-valued-delimited`,
`dns-only`, `values-only`.

LDIF output is RFC 2849-compliant: long lines wrap with leading-space
continuation, values requiring it are Base64-encoded (including the
`dn::` line when the DN contains characters that need encoding).

### Custom delimiter (copy-paste into Excel)

Pick the LDAP filter (`-filter`) and the columns you want (`-requestedAttribute`),
then choose a delimiter. The `delimited` / `multi-valued-delimited` formats emit
one header row of attribute names followed by one row per entry, columns joined
by `-delimiter`:

```powershell
# Tab-separated — paste straight into a worksheet (TAB is Excel's paste delimiter)
.\psldap.ps1 -filter "(objectClass=user)" `
             -requestedAttribute cn,mail,department `
             -delimiter "`t"

# Pipe-separated, multi-valued attributes collapsed into a single cell
.\psldap.ps1 -filter "(objectClass=group)" `
             -requestedAttribute cn,member `
             -outputFormat multi-valued-delimited -delimiter "|"
```

Notes:

- Passing `-delimiter` alone is enough — when `-outputFormat` is omitted it
  implies `delimited`. A delimited format without `-delimiter` defaults to TAB.
- Fields containing the delimiter, a `"`, or a newline are CSV-style quoted
  (inner quotes doubled), so columns stay aligned on paste.
- `multi-valued-delimited` joins an attribute's multiple values with `|` inside
  the cell; plain `delimited` keeps only the first value.

File output is written as **UTF-8 without BOM** so downstream LDIF / CSV
consumers don't choke on the byte-order mark that Windows PowerShell 5.1
otherwise prepends.

## Security notes

- Bind passwords are handled as `SecureString` end-to-end. Plaintext
  passwords are never held in memory longer than necessary; password file
  bytes and decoded characters are zeroed in `finally` blocks.
- Use `-promptForBindPassword` (interactive `Read-Host -AsSecureString`),
  `-bindPasswordFile <path>`, or `-bindPassword <SecureString>`. These
  three options are mutually exclusive.
- `-trustAll` disables certificate validation; use only against test
  servers with self-signed certs.
- The `-redactAttribute` and `-scrambleAttribute` options let you share
  query output without exposing sensitive attribute values. Scrambling
  is deterministic across runs (uses a stable MD5-derived hash, so
  results are reproducible on both Windows PowerShell 5.1 and PowerShell
  7+).

## ldapsearch parameter aliases

Most short-form flags from `ldapsearch` are available as PowerShell
aliases:

| Alias | Parameter             | Alias | Parameter            |
|-------|-----------------------|-------|----------------------|
| `-h`  | `-hostname`           | `-b`  | `-baseDN`            |
| `-p`  | `-port`               | `-s`  | `-scope`             |
| `-D`  | `-bindDN`             | `-z`  | `-sizeLimit`         |
| `-w`  | `-bindPassword`       | `-l`  | `-timeLimitSeconds`  |
| `-j`  | `-bindPasswordFile`   | `-a`  | `-dereferencePolicy` |
| `-q`  | `-useStartTLS`        | `-f`  | `-filterFile`        |
| `-X`  | `-trustAll`           | `-c`  | `-continueOnError`   |
| `-r`  | `-ratePerSecond`      | `-n`  | `-dryRun`            |
| `-T`  | `-dontWrap`           |       |                      |

Note: PowerShell parameter aliases are case-insensitive, so the
ldapsearch flags `-Z`, `-A`, and `-S` are not aliases — use the full
parameter names `-useSSL`, `-typesOnly`, and `-sortOrder` instead.

## Testing

A built-in lightweight test harness runs without Pester or any other
external module:

```powershell
.\run-tests.ps1                # 3 iterations (default)
.\run-tests.ps1 -Iterations 1  # quick smoke test
```

On Windows you can also double-click [run-tests.bat](run-tests.bat).

## License

See repository for license terms.
