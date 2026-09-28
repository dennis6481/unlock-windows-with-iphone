# Created by Rui MA on 28 Sep 2026

# Invoke only the native Components Wizard recovery entry point.

[CmdletBinding()]
param(
    [string]$BuildDirectory = (Join-Path $PSScriptRoot '..\build')
)

$ErrorActionPreference = 'Stop'

$wizard = (Resolve-Path (Join-Path $BuildDirectory 'unlock_windows_components_wizard.exe')).Path
$arguments = @('--resume-uninstall')
$identity = [Security.Principal.WindowsIdentity]::GetCurrent()
$principal = [Security.Principal.WindowsPrincipal]::new($identity)

if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    Start-Process -FilePath $wizard -Verb RunAs -ArgumentList $arguments -Wait
    return
}

& $wizard @arguments
if ($LASTEXITCODE -ne 0) {
    throw "The native Components Wizard recovery entry point returned exit code $LASTEXITCODE."
}
