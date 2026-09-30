:: Created by Rui MA on 29 Sep 2026
@echo off
setlocal
powershell.exe -NoProfile -ExecutionPolicy Bypass -File "%~dp0Install-VmProbe.ps1" -Mode Install
if errorlevel 1 pause
