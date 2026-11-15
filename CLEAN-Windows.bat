@echo off
setlocal
cd /d "%~dp0"
title API Threat Graph - clean
echo.
echo   This deletes ALL data of the last review: the report pages and threat graph
echo   exports in the output folder, and any Docker data still there.
echo   Copy output\site somewhere first if you still need it.
echo.
set /p ok=  Type YES to delete: 
if /i not "%ok%"=="YES" (
  echo   Nothing deleted.
  pause
  exit /b 1
)
docker info >nul 2>nul
if errorlevel 1 (
  echo   Docker Desktop is not running, so its data could not be checked.
  echo   Run this again once Docker Desktop is running.
) else (
  docker compose down -v --remove-orphans >nul 2>nul
  docker compose -f target/docker-compose.yml --profile users down -v --remove-orphans >nul 2>nul
  for /d %%c in (companies\* opensource\*) do if exist "%%c\docker-compose.yml" docker compose -f "%%c\docker-compose.yml" --profile users down -v --remove-orphans >nul 2>nul
  docker volume rm atg_atg-capture atg_atg-telemetry >nul 2>nul
)
if exist output rmdir /s /q output
if exist output (
  echo   Could not delete the output folder. Close any window that has a file from it open, then try again.
  pause
  exit /b 1
)
echo   Done. No data of the review is left in this folder or in Docker.
pause
