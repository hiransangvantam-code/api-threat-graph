@echo off
setlocal EnableDelayedExpansion
cd /d "%~dp0"
title API Threat Graph - all ten open-source systems
rem   DEMO-ALL-Windows.bat                      all ten open-source systems (about 30-40 minutes the first time)
rem   DEMO-ALL-Windows.bat bookinfo petclinic   only these (open-source systems or test companies)
rem   Each system: start it (stand-in services), start ATG on its network, run its users, scan,
rem   copy output\site to demo\<name>\, stop both. Afterwards demo\index.html opens: one card per system.
where docker >nul 2>nul
if errorlevel 1 (echo Docker is not installed. & goto end)
docker info >nul 2>nul
if errorlevel 1 (echo Docker is not running. Start Docker Desktop first, wait for "Engine running". & goto end)
set "SYSTEMS=%*"
if "%SYSTEMS%"=="" set "SYSTEMS=online-boutique bank-of-anthos robot-shop acme-air petclinic piggymetrics lakeside-mutual ftgo hotel-reservation bookinfo"
if not exist demo mkdir demo
set "OK="
set "BAD="
for %%s in (%SYSTEMS%) do call :one %%s
echo.
echo   Done. Reviewed:!OK!
if not "!BAD!"=="" echo   Not reviewed:!BAD!   (run them again alone: DEMO-ALL-Windows.bat ^<name^>)
echo   Opening demo\index.html. Next, the comparison with eight other tools: BENCH-Windows.bat
start "" "%cd%\demo\index.html"
goto end

:one
set "CO=%~1"
set "F=opensource"
if not exist "opensource\%CO%\atg.env" set "F=companies"
if not exist "!F!\%CO%\atg.env" (
  echo == %CO%: no such system, skipped
  set "BAD=!BAD! %CO%"
  exit /b
)
for /f "usebackq eol=# tokens=1,* delims==" %%a in ("!F!\%CO%\atg.env") do set "%%a=%%b"
set TARGET_NAME=!TARGET_NAME:"=!
echo.
echo == %CO% (!TARGET_NAME!)
if "!F!"=="opensource" if not exist "opensource\%CO%\upstream" (
  echo    downloading its code at the pinned commit
  docker run --rm -v "%cd%:/app" -w /app python:3.12-alpine sh -c "apk add --no-cache git >/dev/null && pip install -q pyyaml && python opensource/fetch.py %CO%" >nul 2>nul
  if errorlevel 1 (
    echo    download failed, skipped
    set "BAD=!BAD! %CO%"
    exit /b
  )
)
set "C=docker compose -f !F!/%CO%/docker-compose.yml"
docker compose down -v --remove-orphans >nul 2>nul
echo    starting the system and ATG (first time: a few minutes to build)
!C! up -d --build --wait >nul 2>nul
if errorlevel 1 goto onefail
docker compose up -d --build >nul 2>nul
if errorlevel 1 goto onefail
set /a n=0
:onewait
set /a n+=1
if !n! gtr 90 goto onerun
powershell -NoProfile -Command "try { Invoke-WebRequest -UseBasicParsing -TimeoutSec 2 http://localhost:8080/ | Out-Null; exit 0 } catch { exit 1 }" >nul 2>nul
if errorlevel 1 (
  timeout /t 2 /nobreak >nul
  goto onewait
)
:onerun
echo    users send their requests through the ATG sidecar
!C! run --rm users >nul 2>nul
echo    scanning
docker compose exec -T atg python docker/scan.py --label %CO% --manifests k8s > "demo\%CO%.log" 2>&1
if errorlevel 1 (
  echo    the scan failed: demo\%CO%.log
  set "BAD=!BAD! %CO%"
) else (
  for /f "delims=" %%l in ('findstr /l /b /c:"[scan] %CO%:" "demo\%CO%.log"') do set "LAST=%%l"
  echo    !LAST!
  if exist "demo\%CO%" rmdir /s /q "demo\%CO%"
  robocopy output\site "demo\%CO%" /E >nul
  move /y "demo\%CO%.log" "demo\%CO%\scan.log" >nul
  if "!F!"=="opensource" (
    if not exist results\opensource\atg-laptop mkdir results\opensource\atg-laptop
    docker compose exec -T -e ATG_SYSTEM=%CO% atg python - < opensource\real\dump.py > "results\opensource\atg-laptop\%CO%.json"
  )
  set "OK=!OK! %CO%"
)
docker compose down -v --remove-orphans >nul 2>nul
!C! --profile users down -v --remove-orphans >nul 2>nul
exit /b

:onefail
echo    did not start, skipped ("!C! logs" shows why)
set "BAD=!BAD! %CO%"
docker compose down -v --remove-orphans >nul 2>nul
!C! --profile users down -v --remove-orphans >nul 2>nul
exit /b

:end
echo.
pause
endlocal
