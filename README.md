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

## Output formats

`LDIF` (default), `JSON`, `CSV`, `multi-valued-csv`, `tab-delimited`,
`multi-valued-tab-delimited`, `dns-only`, `values-only`.

LDIF output is RFC 2849-compliant: long lines wrap with leading-space
continuation, values requiring it are Base64-encoded (including the
`dn::` line when the DN contains characters that need encoding).

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
