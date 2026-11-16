@echo off
setlocal
cd /d "%~dp0"
title API Threat Graph
rem   START-Windows.bat                  Bank of Anthos, one of the ten open-source systems (stand-in services)
rem   START-Windows.bat bookinfo         any of the ten open-source systems in opensource\ (see opensource\README.md)
rem   START-Windows.bat shoplite         ShopLite, the development testbed, before and after its fixes
rem   START-Windows.bat paynow           one of the generated test companies in companies\ (development tests)
where docker >nul 2>nul
if errorlevel 1 goto nodocker
docker info >nul 2>nul
if errorlevel 1 goto notrunning
set "CO=%~1"
if "%CO%"=="" set "CO=bank-of-anthos"
if /i not "%CO%"=="shoplite" goto company
echo.
echo   API Threat Graph - two Dockers
echo     company Docker : ShopLite, the system under review  (target\docker-compose.yml)
echo     ATG Docker     : our platform, attached to its network (docker-compose.yml)
echo   ------------------------------------------------------------------------

echo.
echo   Every start is a fresh review: the pages of the previous review in output\site are replaced.
rem versions before 1.3 kept captured traffic in these volumes on disk; remove them if they are still there
docker volume rm atg_atg-capture atg_atg-telemetry >nul 2>nul

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
echo   The threat graph files (GraphML, JSON, SARIF, SVG) are in output\site\exports.
echo   STOP-Windows.bat  stops both Dockers and deletes the review data (pages and exports stay).
echo   CLEAN-Windows.bat deletes the pages and exports too, once you have handed them over.
echo.
pause
exit /b 0

rem ------------------------------------------------------------------ a test company
:company
set "F=companies"
if not exist "companies\%CO%\atg.env" if exist "opensource\%CO%\atg.env" set "F=opensource"
if not exist "%F%\%CO%\atg.env" (
  echo.
  echo   There is no system called "%CO%". The ten test companies are:
  for /d %%c in (companies\*) do if exist "%%c\atg.env" echo     %%~nxc
  echo   and the ten open-source systems ^(stand-ins; real images: REAL-Windows.bat^):
  for /d %%c in (opensource\*) do if exist "%%c\atg.env" echo     %%~nxc
  echo   Example: START-Windows.bat paynow     or     START-Windows.bat bookinfo
  pause
  exit /b 1
)
for /f "usebackq eol=# tokens=1,* delims==" %%a in ("%F%\%CO%\atg.env") do set "%%a=%%b"
set TARGET_NAME=%TARGET_NAME:"=%
if "%F%"=="opensource" if not exist "opensource\%CO%\upstream" (
  echo.
  echo == 0/4 Download %TARGET_NAME% at the pinned commit ^(ATG reads its real deployment files^)
  docker run --rm -v "%cd%:/app" -w /app python:3.12-alpine sh -c "apk add --no-cache git >/dev/null && pip install -q pyyaml && python opensource/fetch.py %CO%"
  if errorlevel 1 goto failed
)
echo.
echo   API Threat Graph - two Dockers
echo     company Docker : %TARGET_NAME%, the system under review  (%F%\%CO%\docker-compose.yml)
echo     ATG Docker     : our platform, attached to its network %TARGET_NETWORK% (docker-compose.yml)
echo   ------------------------------------------------------------------------
echo.
echo   A fresh review: the ATG Docker of any earlier review is stopped first and its data deleted.
docker compose down -v --remove-orphans >nul 2>nul

echo.
echo == 1/4 Company Docker: start %TARGET_NAME% (first time: a few minutes to build)
docker compose -f %F%/%CO%/docker-compose.yml up -d --build --wait
if errorlevel 1 goto failed

echo.
echo == 2/4 ATG Docker: start our platform on the network %TARGET_NETWORK%
docker compose up -d --build
if errorlevel 1 goto failed
echo   Waiting for http://localhost:8080 ...
set /a n=0
:cwait
set /a n+=1
if %n% gtr 90 goto timeout
powershell -NoProfile -Command "try { Invoke-WebRequest -UseBasicParsing -TimeoutSec 2 http://localhost:8080/ | Out-Null; exit 0 } catch { exit 1 }" >nul 2>nul
if errorlevel 1 (
  timeout /t 2 /nobreak >nul
  goto cwait
)
start "" http://localhost:8080/
echo   Opened http://localhost:8080

echo.
echo == 3/4 %TARGET_NAME%'s users send requests; they go through the ATG sidecar
docker compose -f %F%/%CO%/docker-compose.yml run --rm users
if errorlevel 1 goto failed

echo.
echo == 4/4 Scan: Phases 1-4 on %TARGET_NAME%
docker compose exec -T atg python docker/scan.py --label %CO% --manifests k8s
if errorlevel 1 goto failed

echo.
echo   Done. http://localhost:8080 shows %TARGET_NAME%'s threat graph.
if "%F%"=="companies" echo   What was planted in %TARGET_NAME% on purpose: companies\%CO%\README.md
if "%F%"=="opensource" echo   Its labelled weaknesses: opensource\%CO%\system.yaml ^(the services running are stand-ins^)
echo   STOP-Windows.bat stops both Dockers and deletes the review data.
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
