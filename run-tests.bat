@echo off
setlocal

REM The test suite requires PowerShell 7.2+ (psldap.ps1 uses
REM [SHA256]::HashData(), .NET 5+ only — see CHANGELOG 0.3.0). Windows
REM PowerShell 5.1 (powershell.exe) would fail the suite with
REM MissingMethodException, so only pwsh.exe is accepted.
where pwsh.exe >nul 2>&1
if errorlevel 1 (
  echo ERROR: pwsh.exe ^(PowerShell 7.2+^) was not found in PATH.
  echo The test suite requires PowerShell 7.2 or newer; Windows PowerShell
  echo 5.1 is not supported. Install from https://aka.ms/powershell
  endlocal
  exit /b 1
)

REM Default to -Iterations 3 when run with no args; otherwise forward whatever
REM the caller passed straight through to run-tests.ps1.
set "SCRIPT_ARGS=%*"
if "%SCRIPT_ARGS%"=="" set "SCRIPT_ARGS=-Iterations 3"

pwsh.exe -NoProfile -ExecutionPolicy Bypass -File "%~dp0run-tests.ps1" %SCRIPT_ARGS%
set "TEST_EXIT=%ERRORLEVEL%"

endlocal & exit /b %TEST_EXIT%
