@echo off
chcp 65001 >nul
cd /d "%~dp0"
title Confiar en el certificado de GuardianIA
rem Instala la CA local en Windows (solo para su usuario) para que Chrome, Edge y Opera no muestren
rem "La conexion no es privada". Windows pedira confirmar: acepte. Firefox usa su propio almacen.
if exist .venv\Scripts\python.exe (set PY=.venv\Scripts\python.exe) else (set PY=python)
%PY% -m app.tls confiar
echo.
echo Cierre el navegador por completo y vuelva a abrirlo.
pause
