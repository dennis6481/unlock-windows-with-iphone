# Deprecated compatibility wrapper. Normal installation belongs to the native Components Wizard.

[CmdletBinding()]
param(
    [string]$BuildDirectory = (Join-Path $PSScriptRoot '..\build')
)

$ErrorActionPreference = 'Stop'
$wizard = (Resolve-Path (Join-Path $BuildDirectory 'unlock_windows_components_wizard.exe')).Path
Write-Warning 'Direct PowerShell installation is retired. Starting the native Components Wizard.'
Start-Process -FilePath $wizard -Verb RunAs -Wait
