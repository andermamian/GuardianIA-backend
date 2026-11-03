@echo off
chcp 65001 >nul
cd /d "%~dp0"
if exist .venv\Scripts\python.exe (
  echo Usando el entorno virtual .venv
  .venv\Scripts\python.exe arreglar_guardiania.py
) else (
  python arreglar_guardiania.py
)
echo.
pause
