@echo off
setlocal

REM Prefer Windows PowerShell; fall back to PowerShell 7 (pwsh) if it isn't
REM present. Each `where` is gated with `&&` so the check uses that command's
REM own exit code at run time -- reading %ERRORLEVEL% inside an if/else block
REM expands at parse time and would always see the first check's result.
set "PS_CMD="
where powershell.exe >nul 2>&1 && set "PS_CMD=powershell.exe"
if not defined PS_CMD (
  where pwsh.exe >nul 2>&1 && set "PS_CMD=pwsh.exe"
)

if not defined PS_CMD (
  echo ERROR: Neither powershell.exe nor pwsh.exe was found in PATH.
  endlocal
  exit /b 1
)

REM Default to -Iterations 3 when run with no args; otherwise forward whatever
REM the caller passed straight through to run-tests.ps1.
set "SCRIPT_ARGS=%*"
if "%SCRIPT_ARGS%"=="" set "SCRIPT_ARGS=-Iterations 3"

"%PS_CMD%" -NoProfile -ExecutionPolicy Bypass -File "%~dp0run-tests.ps1" %SCRIPT_ARGS%
set "TEST_EXIT=%ERRORLEVEL%"

endlocal & exit /b %TEST_EXIT%
