# Created by Rui MA on 28 Sep 2026

[CmdletBinding()]
param()

$ErrorActionPreference = 'Stop'
$wizard = Join-Path $PSScriptRoot 'build\unlock_windows_components_wizard.exe'

if (-not (Test-Path -LiteralPath $wizard -PathType Leaf)) {
    throw "Components Wizard EXE not found: $wizard`nBuild it first with: make build-release"
}

Start-Process -FilePath $wizard -Verb RunAs
