# AD LDAP Query Toolkit (lightweight, native-only)

A small, dependency-free pair of PowerShell scripts for querying
Active Directory over LDAP from a generic Windows workstation. No
PowerShell modules are required, no RSAT, no admin rights — just
`.NET BCL` classes that ship with every Windows install.

This is a sibling to the larger `psldap.ps1` at the repo root. Use
this toolkit when you want a minimal "starter kit" that is easy to
audit, drop into a CI pipeline, or hand to a junior engineer.

## Files

| File                          | Purpose                                                        |
|-------------------------------|----------------------------------------------------------------|
| `Invoke-AdLdapQuery.ps1`      | The script under test. Defines the `Invoke-AdLdapQuery` fn.    |
| `Test-AdLdapQueryHarness.ps1` | Native-only test harness with offline + live test segregation. |

## Why no modules and why `DirectorySearcher`

- The `ActiveDirectory` PowerShell module is part of RSAT. It is
  **not installed by default** on Windows client editions and is
  often blocked on locked-down workstations. Scripts that depend on
  it are unusable in those environments.
- `System.DirectoryServices.DirectorySearcher` and
  `System.DirectoryServices.DirectoryEntry` are part of the .NET BCL
  on every Windows PowerShell 5.x install. No install, no admin
  required.
- Authentication is implicit Kerberos / GSSAPI via the calling user's
  logon token. **No plaintext credentials** are passed at any point.

## Quick start

### Run the query script directly

```powershell
# One-shot query (script auto-discovers the current domain)
.\Invoke-AdLdapQuery.ps1 -Filter '(objectClass=user)' -MaxResults 5

# Subset of attributes
.\Invoke-AdLdapQuery.ps1 -Filter '(samAccountName=jdoe)' -Properties mail,displayName

# Or dot-source and call the function
. .\Invoke-AdLdapQuery.ps1
Invoke-AdLdapQuery -Filter '(&(objectClass=user)(department=Finance))' -MaxResults 50
```

### Run the test harness

```powershell
# Default: offline tests only (works anywhere, no AD required)
.\Test-AdLdapQueryHarness.ps1

# Full suite on a domain-joined workstation
$env:RUN_LIVE_AD_TESTS = '1'
.\Test-AdLdapQueryHarness.ps1

# Verbose per-test logging
.\Test-AdLdapQueryHarness.ps1 -Detailed

# JSON output for downstream tooling
.\Test-AdLdapQueryHarness.ps1 -Json | Out-File results.json -Encoding utf8
```

### Exit codes

| Code | Meaning                                |
|------|----------------------------------------|
| 0    | All executed tests passed (skips OK)   |
| 1    | At least one test failed               |

## Test segmentation

| Category   | When it runs                                                                                  | Notes                                                    |
|------------|-----------------------------------------------------------------------------------------------|----------------------------------------------------------|
| Offline    | Always.                                                                                       | Safe for non-admin users, locked-down workstations, CI.  |
| Live AD    | Only when `RUN_LIVE_AD_TESTS=1`.                                                              | Requires domain-join. Issues read-only LDAP queries.     |

The harness fails loudly if `RUN_LIVE_AD_TESTS=1` is set but AD is
unreachable — that combination is operator misconfiguration, not a
routine condition.

### Offline tests

Run without any AD connectivity. Cover:

- Script file presence
- `System.DirectoryServices` types loadable
- Script dot-sources cleanly (parser + param-block validity)
- `Invoke-AdLdapQuery` function exported after dot-source
- Empty / whitespace filter rejected before any AD I/O
- Malformed filter (unbalanced parens) rejected locally
- Negative `MaxResults` rejected

### Live AD tests

Run only with `RUN_LIVE_AD_TESTS=1` on a domain-joined machine.
Read-only and safe for any user with normal Domain Users
permissions. Cover:

- AD domain discovery via
  `[System.DirectoryServices.ActiveDirectory.Domain]::GetCurrentDomain()`
- Basic user query (`(objectClass=user)`, MaxResults=5) returns >= 1 result
- Property selection returns exactly the requested attributes
- Nonexistent-account query returns an empty set without throwing
- Returned objects expose `distinguishedName`

## Environment variables

| Variable               | Meaning                                                                   |
|------------------------|---------------------------------------------------------------------------|
| `RUN_LIVE_AD_TESTS`    | `1` to enable live AD tests. Anything else leaves them skipped.           |
| `LIVE_AD_TEST_RETRIES` | Integer N. Up to N additional retry attempts per live test on transient failures (server unavailable, RPC timeout, 0x80072030, etc.). Default `0`. Values `<= 0` and unparseable strings both clamp to "no retries" (one attempt total). |

## GitHub Actions

Two example workflows. Neither is wired up as a live workflow file in
this repo — copy whichever fits your environment into
`.github/workflows/`.

### A. GitHub-hosted runner (offline only)

Runs on `windows-latest`. GitHub-hosted runners are **not** domain-
joined and cannot reach corporate AD. The harness skips live tests
and gates only on offline correctness. Suitable for every PR.

```yaml
name: ad-ldap-toolkit-offline

on:
  pull_request:
    branches: [main]
    paths:
      - 'ad-ldap-query/**'
  push:
    branches: [main]
    paths:
      - 'ad-ldap-query/**'

jobs:
  offline:
    name: Offline tests (Windows-hosted)
    runs-on: windows-latest
    steps:
      - uses: actions/checkout@v4

      - name: Run harness (offline only)
        shell: pwsh
        working-directory: ad-ldap-query
        # RUN_LIVE_AD_TESTS is not set, so live tests SKIP and only
        # offline correctness is gated.
        run: ./Test-AdLdapQueryHarness.ps1
```

### B. Self-hosted runner (full suite, domain-joined)

This workflow only works on a **self-hosted runner that is joined to
your corporate domain**. The runner's service account must be able to
bind to LDAP and read directory objects (any account in `Domain
Users` is enough for the read-only tests). GitHub-hosted runners
cannot run this workflow.

```yaml
name: ad-ldap-toolkit-full

on:
  workflow_dispatch:
  pull_request:
    branches: [main]
    paths:
      - 'ad-ldap-query/**'

jobs:
  full:
    name: Offline + live AD tests (self-hosted)
    # Replace [windows, ad-joined] with whatever labels your runner exposes.
    runs-on: [self-hosted, windows, ad-joined]
    steps:
      - uses: actions/checkout@v4

      - name: Run harness (full)
        shell: pwsh
        working-directory: ad-ldap-query
        env:
          RUN_LIVE_AD_TESTS: '1'
          LIVE_AD_TEST_RETRIES: '2'
        run: ./Test-AdLdapQueryHarness.ps1 -Detailed
```

If your security team requires non-default credentials for the LDAP
bind, do **not** hardcode them in the workflow. Inject them through
GitHub Secrets and have the harness read environment variables — but
the default Kerberos path (current logon token, no creds) is the
preferred design and what this toolkit ships with.

## Validating locally

```powershell
# 1. Confirm the harness runs offline (this is what GitHub-hosted CI does)
$env:RUN_LIVE_AD_TESTS = $null
.\Test-AdLdapQueryHarness.ps1
# Expect: PASS / SKIP only, exit 0

# 2. Confirm the gate works (live tests skip without the env var)
.\Test-AdLdapQueryHarness.ps1 | Select-String 'Live AD tests'
# Expect: "Live AD tests : disabled..."

# 3. Confirm domain discovery works (independent of the harness)
[System.DirectoryServices.ActiveDirectory.Domain]::GetCurrentDomain().Name

# 4. Run the full suite on a domain-joined workstation
$env:RUN_LIVE_AD_TESTS = '1'
.\Test-AdLdapQueryHarness.ps1 -Detailed
# Expect: every PASS or SKIP, exit 0
```

## Common failure modes (and how this design prevents them)

| Failure                                                    | Cause                                                                | This design                                                                                              |
|------------------------------------------------------------|----------------------------------------------------------------------|----------------------------------------------------------------------------------------------------------|
| CI fails on GitHub-hosted runners with "domain not found"  | Stock GitHub runners are not domain-joined.                          | Live tests skip by default; CI never tries to talk to AD unless the operator opts in.                    |
| Malformed filter sends a wasted request to the DC          | DirectorySearcher accepts any string and rejects at FindAll() time.  | `Invoke-AdLdapQuery` runs a parens-balance check first. Bad filters fail locally, no round-trip.         |
| Non-admin user can't load the AD module                    | `Import-Module ActiveDirectory` requires RSAT.                       | This toolkit never imports modules. `DirectorySearcher` is in the .NET BCL on every Windows install.     |
| Plaintext password leaks in logs                           | Passing `-Credential` with a plain string.                           | No credential parameter exists. Auth is implicit Kerberos via the current logon token.                   |
| Test passes locally, fails in CI because of timing         | Transient LDAP / RPC blips on first connection.                      | `LIVE_AD_TEST_RETRIES` env var provides bounded retries with exponential-ish back-off on transient errors. |
| Dot-source for tests accidentally fires the script body    | Top-level statements run on every dot-source.                        | The standalone-invocation block at the bottom guards on `$MyInvocation.InvocationName -ne '.'` and `$Filter`. |
| Test author can't tell offline vs live failures            | Mixed output, opaque failure reasons.                                | Each result row carries a `Status` (`PASS` / `FAIL` / `SKIP`) and a `Message`; `-Json` gives a structured payload. |

## Security notes

- **No plaintext credentials.** The script never accepts a password
  parameter; auth is the calling user's Kerberos token via
  `DirectoryEntry`'s default constructor.
- **Read-only operations.** Every LDAP call is a `DirectorySearcher`
  search. There are no add / modify / delete code paths.
- **No external module install.** The script uses only types from
  `System.DirectoryServices*` namespaces that ship in the .NET BCL.
  A locked-down workstation that can run any PowerShell at all can
  run this.
- **Bounded blast radius.** `MaxResults` defaults to 100 and is
  enforced server-side via `SizeLimit`. A typo cannot accidentally
  page through a million-object directory.
