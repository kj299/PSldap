@echo off
setlocal

set "PS_CMD="
where powershell.exe >nul 2>&1
if %ERRORLEVEL%==0 (
  set "PS_CMD=powershell.exe"
) else (
  where pwsh.exe >nul 2>&1
  if %ERRORLEVEL%==0 set "PS_CMD=pwsh.exe"
)

if not defined PS_CMD (
  echo ERROR: Neither powershell.exe nor pwsh.exe was found in PATH.
  endlocal
  exit /b 1
)

set "SCRIPT_ARGS=%*"
if "%SCRIPT_ARGS%"=="" set "SCRIPT_ARGS=-Iterations 3"

%PS_CMD% -NoProfile -ExecutionPolicy Bypass -File "%~dp0run-tests.ps1" %SCRIPT_ARGS%
set "TEST_EXIT=%ERRORLEVEL%"

endlocal & exit /b %TEST_EXIT%
