@echo off
chcp 65001 >nul
setlocal EnableDelayedExpansion
cd /d "%~dp0"

echo.
echo [Void] Installing dependencies - prefer-binary for faster wheel installs...
echo.

where python >nul 2>&1
if errorlevel 1 (
  echo [!] Python not found in PATH. Install Python 3.10+ and try again.
  pause
  exit /b 1
)

python -m pip install --upgrade pip wheel setuptools
if errorlevel 1 (
  echo [!] pip upgrade failed.
  pause
  exit /b 1
)

python -m pip install -r "%~dp0requirements.txt" --prefer-binary
if errorlevel 1 (
  echo [!] Some packages failed. Check errors above.
  pause
  exit /b 1
)

echo.
echo [+] Done.
echo.
pause
