# Changelog

All notable changes to PSldap are documented here.

## [Unreleased]

CI coverage broadens. No production code changes; no new modules
required (the project's no-install principle still holds).

### Added

- **Windows PowerShell 5.1 leg in `.github/workflows/tests.yml`.**
  The `tests` workflow now matrixes `pwsh` (PowerShell 7+) and
  `powershell` (Windows PowerShell 5.1). The project explicitly
  targets both — the BOM fix in 0.2.1 and the cross-process scramble
  determinism test from 0.2.2 are both 5.1-relevant — and CI
  previously gated only PS 7. Both shells ship on every
  `windows-latest` runner, so no module install or runner change is
  needed.
- **`.github/workflows/ad-ldap-query.yml`** — offline-only CI for the
  `ad-ldap-query/` toolkit, mirroring the "A. GitHub-hosted runner"
  YAML already documented in `ad-ldap-query/README.md`. Matrixes the
  same two PowerShell shells. Live AD tests skip automatically on
  GitHub-hosted runners (no `RUN_LIVE_AD_TESTS=1`); the offline tier
  is now gated on every PR that touches `ad-ldap-query/**`.

### Changed

- **Path filters on `tests.yml`.** The workflow no longer fires for
  unrelated changes (CHANGELOG-only commits, README typos,
  `ad-ldap-query/**` edits). Filters: `psldap.ps1`,
  `psldap.Tests.ps1`, `run-tests.ps1`, and `tests.yml` itself. Pure
  efficiency — the suite still runs on every change that could
  affect it.

### Documentation

- `ad-ldap-query/README.md` now notes that `LIVE_AD_TEST_RETRIES`
  values `<= 0` and unparseable strings both clamp to "no retries"
  (one attempt total).

### Performance

- **`Get-StableStringHash` no longer allocates a fresh `[MD5]` instance
  per call.** Implements Option C from #13 — runtime detection of
  `[MD5]::HashData($bytes)` (PS 7.2+ / .NET 5+, allocation-free
  except for the result array); on Windows PowerShell 5.1, falls
  back to a single cached `[MD5]` instance reused across calls.
  Output is byte-identical on both paths (pinned by the
  `Get-StableStringHash 'hello' = 0x2a40415d` regression test and
  the cross-process determinism test). Single-threaded by design;
  do not call from concurrent runspaces.

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
