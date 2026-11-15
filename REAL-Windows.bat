@echo off
setlocal EnableDelayedExpansion
cd /d "%~dp0"
title API Threat Graph - real images
rem   REAL-Windows.bat robot-shop
rem   Review an open-source system running on its REAL images. The systems: robot-shop petclinic
rem   lakeside-mutual hotel-reservation piggymetrics bookinfo online-boutique (opensource\real\README.md).
rem   Needs Docker Desktop and internet access; the first run of a system downloads its images.
rem   The steps are the same as real.sh. Send back the folder results\opensource\atg-real when done.
set SID=%~1
set K=opensource\real\%SID%
if "%SID%"=="" goto usage
if not exist "%K%\kit.env" goto usage
where docker >nul 2>nul
if errorlevel 1 (echo Docker is not installed. & goto end)
docker info >nul 2>nul
if errorlevel 1 (echo Docker is not running. Start Docker Desktop first. & goto end)

for /f "usebackq eol=# tokens=1,* delims==" %%a in ("%K%\kit.env") do set "%%a=%%b"
for /f "usebackq eol=# tokens=1,* delims==" %%a in ("opensource\%SID%\atg.env") do set "%%a=%%b"
set TARGET_NAME=%TARGET_NAME:"=%
if "%ATG_PORT%"=="" set ATG_PORT=18080
set ATG_SYSTEM=%SID%
rem passwords the system needs: random, in this window's environment only
for %%s in (%SECRETS%) do (
  for /f %%i in ('powershell -NoProfile -Command "[guid]::NewGuid().ToString('N')"') do set "%%s=%%i"
)
set C=docker compose -p real-%SID%
for %%f in (%COMPOSE_FILES%) do set C=!C! -f %%f
set A=docker compose -f docker-compose.yml
if exist "%K%\atg.override.yml" set A=%A% -f %K%\atg.override.yml
if "%WARMUP%"=="" set WARMUP=90
if "%CURL_IMAGE%"=="" set CURL_IMAGE=curlimages/curl:8.11.0

echo.
echo == 1/7 Download %TARGET_NAME% at the pinned commit
if exist "opensource\%SID%\upstream" (
  echo   already there: opensource\%SID%\upstream
) else (
  docker run --rm -v "%cd%:/app" -w /app python:3.12-alpine sh -c "apk add --no-cache git >/dev/null && pip install -q pyyaml && python opensource/fetch.py %SID%"
  if errorlevel 1 goto failed
)

echo.
echo == 2/7 Start %TARGET_NAME% from its real images (first time: downloads, sometimes a build)
%A% down -v --remove-orphans >nul 2>nul
%C% up -d
if errorlevel 1 goto failed
echo   Giving it %WARMUP% s to start up ...
timeout /t %WARMUP% /nobreak >nul

echo.
echo == 3/7 Start ATG on the network %TARGET_NETWORK%
%A% up -d --build
if errorlevel 1 goto failed
set /a n=0
:wait
set /a n+=1
if %n% gtr 90 goto failed
powershell -NoProfile -Command "try { Invoke-WebRequest -UseBasicParsing -TimeoutSec 2 http://localhost:%ATG_PORT%/ | Out-Null; exit 0 } catch { exit 1 }" >nul 2>nul
if errorlevel 1 (
  timeout /t 2 /nobreak >nul
  goto wait
)
echo   ATG is at http://localhost:%ATG_PORT%/

echo.
echo == 4/7 Users: their requests go through the ATG sidecar
if not "%OWN_LOAD%"=="" (
  echo   %TARGET_NAME%'s own load generator (%OWN_LOAD%^), about two minutes
  %C% --profile users run --rm %OWN_LOAD% >nul 2>nul
)
echo   Anonymous requests from %K%\load.txt:
docker run --rm --network %TARGET_NETWORK% -v "%cd%\opensource\real:/kit:ro" --entrypoint sh %CURL_IMAGE% /kit/load.sh /kit/%SID%/load.txt
if errorlevel 1 goto failed

echo.
echo == 5/7 Scan: Phases 1-4
%A% exec -T atg python docker/scan.py --label real-%SID% --manifests k8s
if errorlevel 1 goto failed

echo.
echo == 6/7 Keep the result
if not exist results\opensource\atg-real mkdir results\opensource\atg-real
%A% exec -T -e ATG_SYSTEM=%SID% atg python - < opensource\real\dump.py > results\opensource\atg-real\%SID%.json
if errorlevel 1 goto failed
echo   results\opensource\atg-real\%SID%.json

echo.
echo == 7/7 Stop both Dockers
%C% --profile users down -v --remove-orphans >nul 2>nul
%A% stop >nul 2>nul
echo.
echo   Done. Run the next system, or zip results\opensource\atg-real and send it back.
echo   STOP-Windows.bat removes the ATG Docker and its data when you are finished.
goto end

:usage
echo Usage: REAL-Windows.bat ^<system^>. The systems with a real-image kit are:
for /d %%d in (opensource\real\*) do if exist "%%d\kit.env" echo   %%~nxd
goto end

:failed
echo.
echo Stopped. See the messages above; "docker compose -p real-%SID% logs" shows the system's logs.

:end
echo.
pause
endlocal
