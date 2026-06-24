@echo off
setlocal

cd /d "%~dp0"

cmake -S . -B build
if errorlevel 1 exit /b %errorlevel%

cmake --build build --config Release
if errorlevel 1 exit /b %errorlevel%

echo.
echo Built: %~dp0build\Release\LunaAG-Patch.dll
