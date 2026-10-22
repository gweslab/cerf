@echo off
python "%~dp0build.py" %*
exit /b %ERRORLEVEL%
