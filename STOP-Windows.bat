@echo off
cd /d "%~dp0"
echo Stopping API Threat Graph...
docker compose down
echo Stopped. The pages from the last run are still in the output\site folder.
pause
