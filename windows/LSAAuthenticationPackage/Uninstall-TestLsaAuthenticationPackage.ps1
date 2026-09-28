# Deprecated compatibility wrapper. Normal uninstall belongs to the native Components Wizard.

[CmdletBinding()]
param(
    [string]$BuildDirectory = (Join-Path $PSScriptRoot '..\build'),
    [switch]$RemoveFile
)

$ErrorActionPreference = 'Stop'
if ($RemoveFile) {
    & (Join-Path $PSScriptRoot '..\Recovery\Invoke-ComponentsRecovery.ps1') -BuildDirectory $BuildDirectory
    return
}

$wizard = (Resolve-Path (Join-Path $BuildDirectory 'unlock_windows_components_wizard.exe')).Path
Write-Warning 'Direct PowerShell uninstall is retired. Starting the native Components Wizard.'
Start-Process -FilePath $wizard -Verb RunAs -Wait
