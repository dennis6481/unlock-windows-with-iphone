# Compatibility launcher for the native Components Wizard and read-only diagnostics.

[CmdletBinding()]
param(
    [ValidateSet('Menu', 'Install', 'Unregister', 'RemoveFile', 'Status')]
    [string]$Action = 'Menu',
    [string]$BuildDirectory = (Join-Path $PSScriptRoot '..\build')
)

$ErrorActionPreference = 'Stop'
$wizard = (Resolve-Path (Join-Path $BuildDirectory 'unlock_windows_components_wizard.exe')).Path
$diagnostics = Join-Path $PSScriptRoot '..\Diagnostics\Get-ComponentsStatus.ps1'
$recovery = Join-Path $PSScriptRoot '..\Recovery\Invoke-ComponentsRecovery.ps1'

if ($Action -eq 'Status') {
    & $diagnostics -BuildDirectory $BuildDirectory
    return
}

if ($Action -eq 'RemoveFile') {
    & $recovery -BuildDirectory $BuildDirectory
    return
}

if ($Action -eq 'Menu') {
    Write-Host ''
    Write-Host 'Unlock Windows with iPhone Components' -ForegroundColor Cyan
    Write-Host '1. Open the native Components Wizard'
    Write-Host '2. Show read-only diagnostics'
    Write-Host '3. Run post-restart recovery'
    Write-Host 'Q. Quit'
    switch (Read-Host -Prompt 'Select an action') {
        '1' { $Action = 'Install' }
        '2' { & $diagnostics -BuildDirectory $BuildDirectory; return }
        '3' { & $recovery -BuildDirectory $BuildDirectory; return }
        { $_ -in 'Q', 'q' } { return }
        default { throw 'Unknown action.' }
    }
}

if ($Action -in @('Install', 'Unregister')) {
    Write-Warning 'PowerShell no longer changes component files or registry values. Starting the native wizard.'
    Start-Process -FilePath $wizard -Verb RunAs -Wait
    return
}

throw "Unsupported action '$Action'."
