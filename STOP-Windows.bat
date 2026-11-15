@echo off
setlocal
cd /d "%~dp0"
title API Threat Graph - stop
docker info >nul 2>nul
if errorlevel 1 (
  echo   Docker Desktop is not running, so there is nothing to stop.
  echo   Start Docker Desktop and run this again to delete the review data.
  pause
  exit /b 1
)
echo Stopping both Dockers and deleting the review data...
docker compose down -v --remove-orphans
docker compose -f target/docker-compose.yml --profile users down -v --remove-orphans
for /d %%c in (companies\* opensource\*) do if exist "%%c\docker-compose.yml" docker compose -f "%%c\docker-compose.yml" --profile users down -v --remove-orphans >nul 2>nul
rem versions before 1.3 kept the captured traffic and spans in these volumes on disk
docker volume rm atg_atg-capture atg_atg-telemetry >nul 2>nul
echo.
echo   Deleted: captured traffic, traces, Phase 1 files, EUJF/analysis JSON and the database.
echo   Kept:    output\site (report pages and the threat graph exports).
echo            Delete them with CLEAN-Windows.bat once the report has been handed over.
pause
