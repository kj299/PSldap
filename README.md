# PSldap

A PowerShell implementation inspired by the `ldapsearch` command-line tool.
Query any LDAP directory server using custom filters, scopes, and attribute
selections — with SSL/TLS, StartTLS, paged results, server-side sorting,
multiple output formats, and value transformations (exclude / redact /
scramble).

## Requirements

- **PowerShell 7.2 or newer.** Windows PowerShell 5.1 is no longer supported
  (see CHANGELOG for the 0.3.0 release notes).
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

#### Available delimiters

`-delimiter` accepts **any string** — there is no fixed list. The table below
shows the common choices and how to write them in PowerShell (note that a tab
must be the backtick-escaped `` "`t" `` inside double quotes; the others are
literal characters). Multi-character delimiters such as `" | "` or `"::"` work
too.

| Delimiter        | PowerShell syntax  | When to use                                                        |
|------------------|--------------------|--------------------------------------------------------------------|
| Tab              | `` -delimiter "`t" `` | **Recommended for Excel.** What Excel uses on a clipboard paste; the default when a delimited format is chosen without `-delimiter`. |
| Comma            | `-delimiter ","`   | CSV-style. (Or just use `-outputFormat CSV`, which always uses commas.) |
| Pipe             | `-delimiter "\|"`  | Handy when values may contain commas; also the inner separator for multi-valued cells. |
| Semicolon        | `-delimiter ";"`   | The CSV column separator Excel expects in some locales (e.g. many European ones). |
| Space            | `-delimiter " "`   | Simple eyeballing; values containing spaces get auto-quoted to stay aligned. |
| Custom / literal | `-delimiter "::"`  | Any string is accepted, including multi-character separators.       |

Because any field containing the delimiter is automatically quoted, you can pick
whichever separator is least likely to appear in your data and the columns will
still line up.

File output is written as **UTF-8 without BOM** so downstream LDIF / CSV
consumers don't choke on a byte-order mark.

## Parameters

A grouped summary of the most-used parameters. Run
`Get-Help .\psldap.ps1 -Detailed` (or `-Full`) for the complete list,
defaults, and per-parameter help.

### Connection & TLS

| Parameter        | Default                          | Notes                                                        |
|------------------|----------------------------------|--------------------------------------------------------------|
| `-hostname` (`-h`) | auto-detected domain, else `localhost` | LDAP server name or IP.                                |
| `-port` (`-p`)   | `389` (`636` with `-useSSL`)     | Server port.                                                 |
| `-useSSL`        | off                              | LDAPS (implicit TLS).                                         |
| `-useStartTLS` (`-q`) | off                         | Upgrade a plain connection to TLS. Mutually exclusive with `-useSSL`. |
| `-trustAll` (`-X`) | off                            | Skip certificate validation — **test servers only**.        |

### Authentication

| Parameter                  | Notes                                                              |
|----------------------------|-------------------------------------------------------------------|
| *(none)*                   | Default: integrated auth as the current Windows user (see [Authentication](#authentication)). |
| `-bindDN` (`-D`)           | Bind DN for explicit (simple/Basic) auth.                         |
| `-promptForBindPassword`   | Prompt interactively (`Read-Host -AsSecureString`).               |
| `-bindPassword` (`-w`)     | Password as a `SecureString`.                                     |
| `-bindPasswordFile` (`-j`) | Read the password from the first line of a file.                 |

The three password options are mutually exclusive and each requires `-bindDN`.

### Search

| Parameter                  | Default            | Notes                                                          |
|----------------------------|--------------------|----------------------------------------------------------------|
| `-baseDN` (`-b`)           | derived from domain | Search base.                                                  |
| `-filter`                  | `(objectClass=*)`  | LDAP filter. May be given multiple times for several searches. |
| `-filterFile` (`-f`)       | —                  | File of filters, one per line (`#` comments ignored).          |
| `-ldapURLFile`             | —                  | File of LDAP URLs, each defining base/scope/filter/attributes. |
| `-requestedAttribute`      | all                | Attributes (columns) to return. Repeatable or comma-separated. |
| `-scope` (`-s`)            | `sub`              | `base`, `one`, `sub`, or `subordinates`.                       |
| `-sizeLimit` (`-z`)        | `0` (no limit)     | Max entries the server returns.                                |
| `-timeLimitSeconds` (`-l`) | `0` (no limit)     | Per-search server time budget.                                 |
| `-sortOrder`               | —                  | Server-side sort, e.g. `+sn,-givenName`.                       |
| `-dereferencePolicy` (`-a`)| `never`            | `never`, `always`, `search`, or `find`.                        |

### Output

| Parameter                     | Default | Notes                                                       |
|-------------------------------|---------|-------------------------------------------------------------|
| `-outputFormat`               | `LDIF`  | See [Output formats](#output-formats).                      |
| `-delimiter`                  | TAB (for delimited formats) | Column separator; see [Available delimiters](#available-delimiters). |
| `-outputFile`                 | stdout  | Write results to a file (UTF-8, no BOM).                    |
| `-teeResultsToStandardOut`    | off     | Write to both the file and the console.                     |
| `-separateOutputFilePerSearch`| off     | One output file per filter when running several searches.   |
| `-terse`                      | off     | Suppress summary lines; emit only entries.                  |

### Transformations & flow control

| Parameter             | Notes                                                                       |
|-----------------------|-----------------------------------------------------------------------------|
| `-excludeAttribute`   | Drop these attributes from output.                                          |
| `-redactAttribute`    | Replace these values with `***REDACTED***` (see [Security notes](#security-notes)). |
| `-scrambleAttribute`  | Deterministically scramble these values; `-scrambleRandomSeed` sets the seed. |
| `-continueOnError` (`-c`) | Keep going after a failed search instead of stopping.                   |
| `-dryRun` (`-n`)      | Show the searches that would run without sending them.                       |
| `-requireMatch`       | Exit `1` if no entries matched.                                              |
| `-countEntries`       | Set the exit code to the number of entries returned (capped at 255).        |

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
  is deterministic across runs (uses a stable SHA256-derived hash, so
  results are reproducible across PowerShell 7+ processes). **Note:
  scrambled output for a given `(Value, Seed)` pair changed in 0.3.0
  when the underlying hash moved from MD5 to SHA256.**

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

On Windows you can also use [run-tests.bat](run-tests.bat):

```bat
run-tests.bat                 REM defaults to -Iterations 3
run-tests.bat -Iterations 1   REM forwards args to run-tests.ps1
```

The wrapper detects `powershell.exe` (Windows PowerShell) or `pwsh.exe`
(PowerShell 7+), forwards its arguments to `run-tests.ps1`, and returns the
test process's exit code (so it works in CI), failing with a clear message if
no PowerShell is found.

## License

See repository for license terms.
