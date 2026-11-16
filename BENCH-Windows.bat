@echo off
setlocal
cd /d "%~dp0"
title API Threat Graph - comparison with other tools
rem   The comparison with eight other tools on the ten open-source systems:
rem     DEMO-ALL-Windows.bat   first: ATG reviews the ten systems (results\opensource\atg-laptop\)
rem     BENCH-Windows.bat      then: Checkov, Kubescape, kube-linter, Polaris, Spectral, Bandit, gosec and njsscan
rem                            run on the same ten systems, everything is scored against the same labels,
rem                            and results\opensource\comparison.html opens with every chart and table.
rem   Needs only Docker Desktop and internet (the first run builds the tools image, about 5-10 minutes).
docker info >nul 2>nul
if errorlevel 1 (echo Docker is not running. Start Docker Desktop first. & goto end)
if not exist "results\opensource\atg-laptop\*.json" (echo No ATG results yet: run DEMO-ALL-Windows.bat first. & goto end)
echo.
echo == 1/4 Build the tools image (first time: 5-10 minutes)
docker build -q -t atg-bench-tools -f bench/tools.Dockerfile . >nul
if errorlevel 1 (echo Stopped: the tools image did not build. & goto end)
echo.
echo == 2/4 Run the eight tools on the ten systems (a few minutes)
docker run --rm -v "%cd%:/work" -w /work atg-bench-tools python bench/run_tools.py
if errorlevel 1 (echo Stopped: the tools. & goto end)
echo.
echo == 3/4 Score ATG and the tools against the same labels
docker run --rm -v "%cd%:/work" -w /work atg-bench-tools python bench/compare_tools.py --atg laptop
if errorlevel 1 (echo Stopped: the scoring. & goto end)
echo.
echo == 4/4 Draw the charts
docker run --rm -v "%cd%:/work" -w /work atg-bench-tools python bench/oss_figures.py --atg laptop
if errorlevel 1 (echo Stopped: the charts. & goto end)
echo.
echo   Done. Opening results\opensource\comparison.html (every chart and table).
start "" "%cd%\results\opensource\comparison.html"
:end
echo.
pause
endlocal
