@echo off
REM deploy.bat - double-clickable wrapper around deploy.ps1.
REM
REM It contains no logic and it never will. Logic in two languages is logic that
REM diverges: the day this file grows an "if" is the day Windows deploys start
REM behaving differently depending on which of the two an operator happened to
REM run. Every argument is passed straight through, so
REM
REM     deploy.bat -Profile full -EnableHooks
REM
REM is exactly deploy.ps1 with those switches.
REM
REM -NoProfile so a user's PowerShell profile cannot change what a deploy does.
REM -ExecutionPolicy Bypass for this process only; it changes no machine policy.

powershell -NoProfile -ExecutionPolicy Bypass -File "%~dp0deploy.ps1" %*
exit /b %ERRORLEVEL%
