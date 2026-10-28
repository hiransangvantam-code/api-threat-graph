@echo off
setlocal
cd /d "%~dp0"
title API Threat Graph
echo.
echo   API Threat Graph - start with Docker
echo   ------------------------------------
where docker >nul 2>nul
if errorlevel 1 goto nodocker
docker info >nul 2>nul
if errorlevel 1 goto notrunning

echo   Building and starting. The first time downloads about 300 MB
echo   and takes a few minutes. Later starts take about a minute.
echo.
docker compose up --build -d
if errorlevel 1 goto failed

echo.
echo   Waiting for http://localhost:8080 ...
set /a n=0
:wait
set /a n+=1
if %n% gtr 120 goto timeout
powershell -NoProfile -Command "try { Invoke-WebRequest -UseBasicParsing -TimeoutSec 2 http://localhost:8080/ | Out-Null; exit 0 } catch { exit 1 }" >nul 2>nul
if errorlevel 1 (
  timeout /t 2 /nobreak >nul
  goto wait
)
start "" http://localhost:8080/
echo.
echo   Opened http://localhost:8080 in your browser.
echo   The threat graph appears there after about a minute.
echo.
echo   To stop: double-click STOP-Windows.bat
echo   Closing this window does NOT stop the program. Live log below:
echo.
docker compose logs -f --tail 20 atg
exit /b 0

:nodocker
echo   Docker is not installed. Install Docker Desktop first:
echo   https://www.docker.com/products/docker-desktop/
echo   then double-click this file again.
pause
exit /b 1

:notrunning
echo   Docker Desktop is not running. Open Docker Desktop, wait until
echo   it says "Engine running", then double-click this file again.
pause
exit /b 1

:failed
echo.
echo   Building or starting failed. Read the messages above.
echo   Port 8080 already in use? Close the program using it, or see HOW-TO-RUN.md.
pause
exit /b 1

:timeout
echo   The page did not come up. Last lines of the log:
docker compose logs --tail 60 atg
pause
exit /b 1
