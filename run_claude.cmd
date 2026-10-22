@echo off
python "%~dp0run_claude.py" %*
exit /b %ERRORLEVEL%
