# Changelog

All notable changes to PSldap are documented here.

## [Unreleased]

_No changes yet._

## [0.3.0] - 2026-06-21

> ⚠️ **BREAKING.** Two
> independent breaking changes; both are explicit choices documented
> below.
>
> 1. **`-scrambleAttribute` output changes for every input.** The
>    underlying stable hash moved from MD5 to SHA256. Any anonymized
>    exports generated with prior versions are *not reproducible* by
>    this version using the same `-scrambleRandomSeed`. Re-run
>    scrambling jobs if you need fresh output that downstream consumers
>    can re-derive.
> 2. **Windows PowerShell 5.1 is no longer supported.** The minimum is
>    now PowerShell 7.2. Both `psldap.ps1` and the `ad-ldap-query/`
>    toolkit drop the 5.1 leg from CI and remove all 5.1-targeting
>    code paths.

### Removed

- **Windows PowerShell 5.1 support.** `psldap.ps1` now requires
  PowerShell 7.2+ because `Get-StableStringHash` uses the static
  `[SHA256]::HashData()` method (.NET 5+ only). The PS 5.1 jobs are
  removed from both `.github/workflows/tests.yml` and
  `.github/workflows/ad-ldap-query.yml`. The `ad-ldap-query/` toolkit
  followed the same line for consistency.

### Changed

- **`Get-StableStringHash` algorithm: MD5 → SHA256.** Implements
  Option B from #15. The function now calls
  `[System.Security.Cryptography.SHA256]::HashData($bytes)` — static,
  no instance, no `IDisposable`, inherently thread-safe. Only the
  first 4 bytes of the SHA256 digest are kept and interpreted as a
  signed Int32, so this is still a non-cryptographic stable mixer;
  the change does not strengthen the scrambler's privacy properties,
  but the choice of algorithm now satisfies audit/scanner readings
  that flag MD5 by name. **Pinned regression test updated from
  `0x2a40415d` (MD5) to `-1169296852` / `0xba4df22c` (SHA256).** The
  cross-process determinism test still passes — the algorithm
  changed but the determinism property is preserved.
- **Path filters on `tests.yml`.** The workflow no longer fires for
  unrelated changes (CHANGELOG-only commits, README typos,
  `ad-ldap-query/**` edits). Filters: `psldap.ps1`,
  `psldap.Tests.ps1`, `run-tests.ps1`, and `tests.yml` itself. Pure
  efficiency — the suite still runs on every change that could
  affect it.

### Added

- **`run-tests.bat` now works with either PowerShell and propagates the
  exit code.** Detects `powershell.exe` (Windows PowerShell) or
  `pwsh.exe` (PowerShell 7+), forwards its arguments to `run-tests.ps1`
  (defaulting to `-Iterations 3` when none are given), returns the test
  process's exit code so it can gate CI, and fails with a clear message
  if no PowerShell is found. The shell detection uses `&&` on each
  `where` check rather than reading `%ERRORLEVEL%` inside an `if/else`
  block (which expands at parse time and would never reach the
  `pwsh.exe` fallback). Reworks the idea from #16 with that bug fixed.
  *(Note: the detection logic is retained — the wrapper still finds
  whichever PowerShell is on PATH — but only `pwsh.exe` will actually
  run the suite to completion now; `powershell.exe` will fail in
  `Get-StableStringHash` because the underlying SHA256 static method
  is .NET 5+.)*
- **`-Iterations` validation in `run-tests.ps1`.** Adds
  `[ValidateRange(1, [int]::MaxValue)]` so non-positive iteration counts
  are rejected up front instead of silently running zero iterations.
  (From #16.)
- **`delimited` / `multi-valued-delimited` output formats with a
  `-delimiter` parameter.** Emits a header row of attribute names plus
  one row per entry, columns joined by a caller-chosen delimiter, for
  output that pastes cleanly into Excel. Combine with `-filter` (which
  LDAP filter) and `-requestedAttribute` (which columns). Passing
  `-delimiter` alone implies the `delimited` format; a delimited format
  without `-delimiter` defaults to TAB (Excel's clipboard-paste
  separator). Fields containing the delimiter, a `"`, or a newline are
  CSV-style quoted so columns stay aligned. The existing `tab-delimited`
  formats now share this engine (`Format-DelimitedOutput`) and gain the
  same quoting; `Format-TabOutput` is a thin TAB wrapper. Covered by new
  `Format-DelimitedField` / `Format-DelimitedOutput` unit tests.
- **`.github/workflows/ad-ldap-query.yml`** — offline-only CI for the
  `ad-ldap-query/` toolkit, mirroring the "A. GitHub-hosted runner"
  YAML already documented in `ad-ldap-query/README.md`. Live AD tests
  skip automatically on GitHub-hosted runners (no `RUN_LIVE_AD_TESTS=1`);
  the offline tier is gated on every PR that touches `ad-ldap-query/**`.

### Documentation

- **`README.md` usage reference expanded.** Adds an "Available
  delimiters" table (clarifying that `-delimiter` takes any string, with
  the PowerShell syntax for tab/comma/pipe/semicolon/space/custom and a
  note that fields are auto-quoted) and a grouped "Parameters" section
  (connection/TLS, authentication, search, output, transformations &
  flow control) with defaults and aliases, pointing to
  `Get-Help -Detailed` for the full reference.
- **`README.md` now has an "Authentication" section.** Documents that
  the default bind (no `-bindDN` / password) uses `AuthType::Negotiate`
  with the current Windows logon, so queries run against Active
  Directory as the calling user (Kerberos/NTLM via SSPI) with no
  module install and no plaintext password. Notes that supplying
  `-bindDN` + a password option switches to explicit `Basic` auth, and
  that the integrated path targets on-prem AD, not cloud-only Entra ID.
- **Minimum-version statement** updated to PowerShell 7.2+ across
  `README.md`, `ad-ldap-query/README.md`, and the harness file.
- `ad-ldap-query/README.md` now notes that `LIVE_AD_TEST_RETRIES`
  values `<= 0` and unparseable strings both clamp to "no retries"
  (one attempt total).

## [0.2.2] - 2026-04-27

Regression-coverage and CI infrastructure release. Adds dedicated
tests for the two fixes from 0.2.1 that previously had none, wires
up GitHub Actions to gate merges on the test suite, and tightens
test-harness hygiene.

### Added

- **GitHub Actions workflow** (`.github/workflows/tests.yml`). Runs
  `run-tests.ps1 -Iterations 3` on `windows-latest` for every push to
  `main` and every pull request targeting `main`. Gates merges on
  test-suite green.

### Tests

- Added `Write-SearchOutput writes UTF-8 without BOM to output file` —
  reads the first three bytes of the produced file and asserts they
  are not `EF BB BF`. Catches any future regression that re-introduces
  a BOM in file output.
- Added `Invoke-ScrambleValue is deterministic across separate
  PowerShell processes` — spawns a child `pwsh` via `-EncodedCommand`,
  runs the same scramble there, and asserts the output matches the
  in-process result. Catches any regression to
  `String.GetHashCode()`-based hashing (which is randomized per
  process on PowerShell 7+). Asserts `$LASTEXITCODE -eq 0` first so a
  child-process failure surfaces with a clear message instead of a
  confusing value mismatch.
- Added a `Describe 'Get-StableStringHash'` block with four tests:
  empty / `$null` return `0`, a pinned MD5-derived Int32 value for
  `"hello"` (`0x2a40415d`), and a basic in-process determinism check.
  The pinned value catches algorithm changes, endianness regressions,
  and UTF-8 vs. UTF-16 encoding regressions without spawning a
  subprocess.
- Added a `Describe 'Source-Code Checks'` block with a test asserting
  `psldap.ps1` does not reference `[LinkedHashSet]`. The type doesn't
  exist in .NET; a regression to it crashed CSV / tab output at
  runtime in a previous version. Static check, no LDAP connection
  required.

### Changed

- `run-tests.ps1` now `exit 1`s when any test fails (sum of failures
  across all iterations). Previously the script always exited 0, so
  CI couldn't gate on test failures.

### Documentation

- Test harness now notes that dot-sourcing `psldap.ps1` imports its
  `param()` block as variables in the test scope (e.g. `$hostname`,
  `$port`, `$baseDN`, `$filter`, `$scope`), so future test authors
  avoid accidental name collisions.

## [0.2.1] - 2026-04-25

Hardening release: removes a latent script-load failure, fixes RFC
compliance gaps, and improves cross-runtime determinism. No new modules
required — the script still relies only on .NET BCL assemblies that
ship with Windows.

### Fixed

- **Script-load failure (regression blocker).** The param block declared
  case-conflicting aliases — `-Z` / `-z`, `-A` / `-a`, `-S` / `-s` —
  which PowerShell treats as duplicates because parameter aliases are
  case-insensitive. The script failed to parse on every invocation with
  `The alias "z" is declared multiple times`. Removed the uppercase
  aliases; use `-useSSL`, `-typesOnly`, and `-sortOrder` (the full
  names) in place of ldapsearch's `-Z`, `-A`, `-S`.
- **`LinkedHashSet` runtime crash on CSV / tab output.** When CSV or
  tab output was requested without `-requestedAttribute`, the column-
  inference path tried to instantiate
  `[System.Collections.Generic.LinkedHashSet[string]]` — a Java type
  that does not exist in .NET. Replaced with a `HashSet[string]` +
  `List[string]` pair to preserve insertion order without the missing
  type.
- **LDIF `dn::` Base64 encoding (RFC 2849).** DNs containing leading
  spaces, non-ASCII, or control characters were emitted as plain
  `dn: <raw>` instead of `dn:: <base64>`. Routed the DN line through
  the same `Test-NeedsBase64` check used for attribute values.
- **Scramble determinism on PowerShell 7+.** `Invoke-ScrambleValue` used
  `String.GetHashCode()`, which is randomized per process on
  .NET Core / .NET 5+. Scrambled output therefore differed between
  runs on PowerShell 7. Replaced with a stable MD5-derived Int32 hash
  (`Get-StableStringHash`) — non-cryptographic use, native to .NET, no
  module install. Output is now reproducible across runs and across
  Windows PowerShell 5.1 ↔ PowerShell 7+.
- **UTF-8 BOM in file output.** `Out-File -Encoding UTF8` writes a BOM
  on Windows PowerShell 5.1, breaking strict LDIF consumers (RFC 2849
  forbids the BOM) and tripping up many CSV parsers. File output now
  goes through `[System.IO.File]::WriteAllText` with
  `UTF8Encoding($false)`.

### Changed

- **Test harness no longer regex-extracts function definitions.**
  `psldap.Tests.ps1` now dot-sources `psldap.ps1`. The script's main
  execution block is guarded with
  `if ($MyInvocation.InvocationName -eq '.') { return }` so dot-sourcing
  loads helpers without firing connection / search logic. The previous
  approach broke whenever the source file's section banners were
  reformatted.

### Documentation

- Rewrote `README.md` to describe the current ldapsearch-style tool
  (the previous README still referenced the pre-uplift script that was
  removed in `957ef17`).
- Added this changelog.

### Tests

- Added a positive `dn::` Base64 LDIF test and a negative test
  asserting plain `dn:` for printable-ASCII DNs (the previous edge-case
  test was a false positive).
- Test suite: **90 / 90** passing across 3 stability iterations.

## [0.2.0] - prior

Major uplift to an `ldapsearch`-style query tool with security
hardening (commit `f9d6b45`). This was a near-complete rewrite of the
original script. Highlights:

- Switched from interactive prompting + `Get-ADUser` (which required
  the ActiveDirectory module) to direct
  `System.DirectoryServices.Protocols` calls with no module
  dependency.
- Full ldapsearch-style parameter surface: connection, search,
  output, and transformation options.
- Output formats: LDIF, JSON, CSV, multi-valued CSV, tab-delimited,
  multi-valued tab-delimited, dns-only, values-only.
- Paged results, server-side sorting, alias dereferencing, time /
  size limits, rate limiting, dry-run mode.
- File-based input: filter files (one filter per line) and LDAP-URL
  files (multiple searches with per-search baseDN / scope /
  attributes / filter).
- Transformations: `-excludeAttribute`, `-redactAttribute`,
  `-scrambleAttribute`.
- Security hardening: `SecureString` end-to-end, byte-array zeroing
  of password material in `finally`, mutually-exclusive credential
  options, basic LDAP-filter syntax validation.
- Built-in lightweight test harness (no Pester required).

## [v0.1-alpha] - 2023-04-16

Original `Get-ADUser`-based script that prompted the user for an LDAP
filter and queried the current AD domain. Required the
`ActiveDirectory` module.
