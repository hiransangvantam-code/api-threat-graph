@echo off
setlocal
cd /d "%~dp0"
title API Threat Graph
echo.
echo   API Threat Graph - two Dockers
echo     company Docker : ShopLite, the system under review  (target\docker-compose.yml)
echo     ATG Docker     : our platform, attached to its network (docker-compose.yml)
echo   ------------------------------------------------------------------------
where docker >nul 2>nul
if errorlevel 1 goto nodocker
docker info >nul 2>nul
if errorlevel 1 goto notrunning

echo.
echo == 1/6 Company Docker: start ShopLite as shipped (first time: a few minutes to build)
set SHOPLITE_HARDENED=0
set SHOPLITE_MANIFESTS=k8s
docker compose -f target/docker-compose.yml up -d --build --wait
if errorlevel 1 goto failed

echo.
echo == 2/6 ATG Docker: start our platform (sidecar proxy, OTel Collector, PostgreSQL, scanner, web)
docker compose up -d --build
if errorlevel 1 goto failed
echo   Waiting for http://localhost:8080 ...
set /a n=0
:wait
set /a n+=1
if %n% gtr 90 goto timeout
powershell -NoProfile -Command "try { Invoke-WebRequest -UseBasicParsing -TimeoutSec 2 http://localhost:8080/ | Out-Null; exit 0 } catch { exit 1 }" >nul 2>nul
if errorlevel 1 (
  timeout /t 2 /nobreak >nul
  goto wait
)
start "" http://localhost:8080/
echo   Opened http://localhost:8080 - it shows both Dockers until the first scan is done.

echo.
echo == 3/6 Customers use the shop; their traffic goes through the ATG sidecar
docker compose -f target/docker-compose.yml run --rm users
if errorlevel 1 goto failed

echo.
echo == 4/6 Scan 1: Phases 1-4 on ShopLite as shipped
docker compose exec -T atg python docker/scan.py --label vulnerable --manifests k8s
if errorlevel 1 goto failed

echo.
echo == 5/6 The company deploys the fixes; customers use the shop again
set SHOPLITE_HARDENED=1
set SHOPLITE_MANIFESTS=k8s-hardened
docker compose -f target/docker-compose.yml up -d --wait
if errorlevel 1 goto failed
docker compose -f target/docker-compose.yml run --rm users
if errorlevel 1 goto failed

echo.
echo == 6/6 Scan 2: Phases 1-4 on ShopLite with the fixes
docker compose exec -T atg python docker/scan.py --label hardened --manifests k8s-hardened
if errorlevel 1 goto failed

echo.
echo   Done. http://localhost:8080 shows the threat graph, both scans and the trend.
echo   To stop both Dockers: double-click STOP-Windows.bat
echo.
pause
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
echo   A step failed. Read the messages above.
echo   Port 8080 already in use? Close the program using it, or see HOW-TO-RUN.md.
pause
exit /b 1

:timeout
echo   The ATG page did not come up. Last lines of its log:
docker compose logs --tail 60 atg
pause
exit /b 1
