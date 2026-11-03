@echo off
chcp 65001 >nul
cd /d "%~dp0"
title GuardianIA (HTTPS)
rem Arranca GuardianIA por HTTPS en la red local: https://127.0.0.1:8443 en este PC y
rem https://IP-del-PC:8443 para el celular. http://...:8000 redirige solo a HTTPS.
rem Para usarlo SOLO en este PC: INICIAR_SOLO_ESTE_PC.bat
if exist .venv\Scripts\python.exe (set PY=.venv\Scripts\python.exe) else (set PY=python)
echo Revisando dependencias...
%PY% -m pip install -q -r requirements.txt
%PY% -m app.servidor --abrir dispositivos
pause
