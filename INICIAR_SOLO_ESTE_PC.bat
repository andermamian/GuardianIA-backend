@echo off
chcp 65001 >nul
cd /d "%~dp0"
title GuardianIA (HTTPS, solo este PC)
rem Igual que INICIAR_GUARDIANIA.bat, pero nadie de la red puede entrar (el celular tampoco).
if exist .venv\Scripts\python.exe (set PY=.venv\Scripts\python.exe) else (set PY=python)
%PY% -m pip install -q -r requirements.txt
%PY% -m app.servidor --solo-local --abrir proteccion/antivirus
pause
