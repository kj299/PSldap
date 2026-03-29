@echo off
powershell.exe -NoProfile -ExecutionPolicy Bypass -File "%~dp0run-tests.ps1" -Iterations 3
pause
