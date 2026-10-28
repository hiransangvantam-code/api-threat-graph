@echo off
cd /d "%~dp0"
echo Stopping the ATG platform and the company's system...
docker compose down
docker compose -f target/docker-compose.yml --profile users down
echo Stopped. The pages of the last run are still in the output\site folder.
pause
