# Created by Rui MA on 28 Sep 2026

function Get-NativeWindowsArchitecture {
    [CmdletBinding()]
    param()

    # PROCESSOR_ARCHITEW6432 reports the native OS architecture when a
    # 32-bit PowerShell process is running under WOW64. Prefer it over
    # PROCESSOR_ARCHITECTURE for that case.
    $reportedArchitectures = @(
        $env:PROCESSOR_ARCHITEW6432
        $env:PROCESSOR_ARCHITECTURE
    ) | Where-Object { $_ }

    foreach ($architecture in $reportedArchitectures) {
        switch ($architecture.ToUpperInvariant()) {
            { $_ -in @('ARM64', 'ARM64EC') } { return 'arm64' }
            { $_ -in @('AMD64', 'X64') } { return 'x64' }
        }
    }

    $reportedArchitectureText = $reportedArchitectures -join ', '
    throw "Unsupported native Windows processor architecture value(s): $reportedArchitectureText. Only x64 and ARM64 are supported."
}

function Get-PortableExecutableArchitecture {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string]$Path
    )

    $resolvedPath = (Resolve-Path -LiteralPath $Path -ErrorAction Stop).Path
    $stream = [System.IO.File]::Open(
        $resolvedPath,
        [System.IO.FileMode]::Open,
        [System.IO.FileAccess]::Read,
        [System.IO.FileShare]::Read
    )

    try {
        if ($stream.Length -lt 0x40) {
            throw "'$resolvedPath' is too small to be a PE file."
        }

        $dosHeader = New-Object byte[] 0x40
        if ($stream.Read($dosHeader, 0, $dosHeader.Length) -ne $dosHeader.Length) {
            throw "Could not read the DOS header from '$resolvedPath'."
        }

        if ([BitConverter]::ToUInt16($dosHeader, 0) -ne 0x5A4D) {
            throw "'$resolvedPath' does not have an MZ header."
        }

        $peHeaderOffset = [BitConverter]::ToInt32($dosHeader, 0x3C)
        if ($peHeaderOffset -lt 0x40 -or $peHeaderOffset -gt ($stream.Length - 6)) {
            throw "'$resolvedPath' has an invalid PE header offset."
        }

        $stream.Seek($peHeaderOffset, [System.IO.SeekOrigin]::Begin) | Out-Null
        $coffHeader = New-Object byte[] 6
        if ($stream.Read($coffHeader, 0, $coffHeader.Length) -ne $coffHeader.Length) {
            throw "Could not read the PE header from '$resolvedPath'."
        }

        if ([BitConverter]::ToUInt32($coffHeader, 0) -ne 0x00004550) {
            throw "'$resolvedPath' does not have a PE signature."
        }

        switch ([BitConverter]::ToUInt16($coffHeader, 4)) {
            0x8664 { return 'x64' }
            0xAA64 { return 'arm64' }
            default {
                $machine = [BitConverter]::ToUInt16($coffHeader, 4).ToString('X4')
                throw "'$resolvedPath' has unsupported PE machine type 0x$machine."
            }
        }
    } finally {
        $stream.Dispose()
    }
}

function Get-CurrentPowerShellArchitecture {
    [CmdletBinding()]
    param()

    $processPath = (Get-Process -Id $PID -ErrorAction Stop).Path
    return Get-PortableExecutableArchitecture -Path $processPath
}

if ($MyInvocation.InvocationName -ne '.') {
    Get-NativeWindowsArchitecture
}
