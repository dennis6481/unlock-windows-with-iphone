# Created by Rui MA on 28 Sep 2026

[CmdletBinding()]
param(
    [Parameter(Position = 0)][string]$PackageVersion,
    [Parameter(Position = 1)][string]$PackageResourcePath,
    [Parameter(Position = 2)][string]$PackageManifestPath,
    [Parameter(Position = 3)][string]$DesktopFileList,
    [Parameter(Position = 4, ValueFromRemainingArguments)][string[]]$PackageFiles
)

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

function Write-EmbeddedPackage {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$Version,
        [Parameter(Mandatory)][string]$ResourcePath,
        [Parameter(Mandatory)][string]$ManifestPath,
        [Parameter(Mandatory)][string]$DesktopFileList,
        [Parameter(Mandatory)][string[]]$Files
    )

    $ErrorActionPreference = 'Stop'
    $contract = [IO.File]::ReadAllText((Join-Path $PSScriptRoot 'ComponentFiles.h'))
    $names = @{}
    foreach ($match in [regex]::Matches($contract, 'wchar_t\s+(\w+)\[\] = L"([^"]+)";')) {
        $names[$match.Groups[1].Value] = $match.Groups[2].Value
    }
    $components = @([regex]::Matches($contract, '\{(k\w+File), (true|false)\}') | ForEach-Object {
        [pscustomobject]@{ Name=$names[$_.Groups[1].Value]; Desktop=$_.Groups[2].Value -eq 'true' }
    })
    if (!$components.Count) { throw 'Component contract is empty.' }
    $parts = $Version.Split('.')
    if ($parts.Count -ne 3) { throw "Invalid product version: $Version" }
    $entries = [Collections.Generic.List[object]]::new()
    $seen = [Collections.Generic.HashSet[string]]::new([StringComparer]::OrdinalIgnoreCase)
    $architecture = $null
    foreach ($component in $components) {
        $matches = @($Files | Where-Object { [IO.Path]::GetFileName($_) -ceq $component.Name })
        if ($component.Name -ceq $names.kInstallerFile) { continue }
        if ($matches.Count -ne 1) { throw "Expected one product component: $($component.Name)" }
        $path = (Resolve-Path -LiteralPath $matches[0]).Path
        $info = [Diagnostics.FileVersionInfo]::GetVersionInfo($path)
        if ($info.ProductVersion -cne $Version -or $info.FileVersion -cne $Version -or
            $info.ProductPrivatePart -ne 0 -or $info.FilePrivatePart -ne 0 -or
            $info.ProductMajorPart -ne [int]$parts[0] -or $info.FileMajorPart -ne [int]$parts[0] -or
            $info.ProductMinorPart -ne [int]$parts[1] -or $info.FileMinorPart -ne [int]$parts[1] -or
            $info.ProductBuildPart -ne [int]$parts[2] -or $info.FileBuildPart -ne [int]$parts[2]) {
            throw "Mixed or missing product/file version: $path"
        }
        $arch = Get-PortableExecutableArchitecture -Path $path
        if ($architecture -and $arch -cne $architecture) { throw "Mixed product architecture: $path" }
        $architecture = $arch
        if (!$seen.Add($component.Name)) { throw "Duplicate product filename: $($component.Name)" }
        $entries.Add([pscustomobject]@{Name=$component.Name;Path=$path;Desktop=$component.Desktop;Product=$true})
    }
    if ($Files.Count -ne $entries.Count) { throw 'Unexpected product component input.' }
    $schema = [IO.File]::ReadAllText((Join-Path $PSScriptRoot 'Setup/PackageManifest.h'))
    $pathPattern = [regex]::Match($schema, '(?s)kPackagePathComponentPattern\[\]\s*=\s*LR"regex\((.*?)\)regex";').Groups[1].Value
    if (!$pathPattern) { throw 'Missing package relative path policy.' }
    $desktopRoot = [IO.Path]::GetDirectoryName((Resolve-Path -LiteralPath $DesktopFileList).Path)
    foreach ($name in [IO.File]::ReadAllLines($DesktopFileList)) {
        if ([IO.Path]::IsPathRooted($name) -or
            @($name -split '[/\\]' | Where-Object { $_ -notmatch ('\A(?:'+$pathPattern+')\z') }).Count) {
            throw "Unsafe desktop relative path: $name"
        }
        if ($name -ceq $names.kMainAppFile) { continue }
        if (!$seen.Add($name)) { throw "Duplicate desktop relative path: $name" }
        $entries.Add([pscustomobject]@{Name=$name;Path=(Join-Path $desktopRoot $name);Desktop=$true;Product=$false})
    }
    $constants = @{}
    foreach ($match in [regex]::Matches($schema, 'uint32_t (kPackage\w+) = (\d+);')) {
        $constants[$match.Groups[1].Value] = [uint32]$match.Groups[2].Value
    }
    $readFields = {
        param([string]$Type)
        $declarations = [regex]::Matches($schema, ('(?s)struct '+$Type+' final \{(.*?)\};'))
        if ($declarations.Count -ne 1) { throw "Missing or ambiguous package schema: $Type" }
        $body = $declarations[0].Groups[1].Value
        $offset = 0
        while ($body.Substring($offset).Trim()) {
            $field = [regex]::Match($body.Substring($offset),
                '\A\s*(std::uint32_t|unlock_windows::protocol::Sha256Digest)\s+(\w+);')
            if (!$field.Success) { throw "Unsupported package schema field in $Type." }
            [pscustomobject]@{ Type=$field.Groups[1].Value; Name=$field.Groups[2].Value }
            $offset += $field.Length
        }
    }
    $headerFields = @(& $readFields 'PackageManifestHeader')
    $recordFields = @(& $readFields 'PackageRecord')
    $crypto = [IO.File]::ReadAllText((Join-Path $PSScriptRoot 'Protocol/UnlockCrypto.h'))
    $digestDefinition = [regex]::Matches($crypto, 'using Sha256Digest = std::array<std::uint8_t, (\d+)>;')
    if (!$headerFields.Count -or !$recordFields.Count -or $constants.Count -ne 5 -or $digestDefinition.Count -ne 1) {
        throw 'Invalid package manifest schema.'
    }
    $digestSize = [int]$digestDefinition[0].Groups[1].Value
    $resourceLines = @('// Created by Rui MA on 09 Oct 2026', '', '#pragma code_page(65001)', '#include <windows.h>')
    $memory = [IO.MemoryStream]::new()
    $writer = [IO.BinaryWriter]::new($memory)
    $writeRecord = {
        param([object[]]$Fields, [hashtable]$Values)
        foreach ($field in $Fields) {
            if (!$Values.ContainsKey($field.Name)) { throw "Missing package field value: $($field.Name)" }
            switch ($field.Type) {
                'std::uint32_t' { $writer.Write([uint32]$Values[$field.Name]) }
                'unlock_windows::protocol::Sha256Digest' {
                    $digest = [byte[]]$Values[$field.Name]
                    if ($digest.Length -ne $digestSize) { throw 'Invalid package digest size.' }
                    $writer.Write($digest)
                }
                default { throw "Unsupported package field type: $($field.Type)" }
            }
        }
    }
    try {
        & $writeRecord $headerFields @{magic=$constants.kPackageManifestMagic;
            version=$constants.kPackageManifestVersion; count=($entries.Count + 1)}
        $id = 1
        foreach ($entry in $entries) {
            if ($id -ge $constants.kPackageManifestResourceId) { throw 'Too many package files.' }
            $item = Get-Item -LiteralPath $entry.Path -Force
            if ($item.PSIsContainer -or $item.Length -eq 0 -or $item.Length -gt [uint32]::MaxValue) {
                throw "Invalid package file: $($entry.Path)"
            }
            $parent = $item
            while ($parent) {
                if ($parent.Attributes -band [IO.FileAttributes]::ReparsePoint) { throw "Unsafe package source: $($parent.FullName)" }
                $parent = if ($parent -is [IO.FileInfo]) { $parent.Directory } else { $parent.Parent }
            }
            $data = [IO.File]::ReadAllBytes($item.FullName)
            $machine = 0
            if ($data.Length -ge 2 -and [BitConverter]::ToUInt16($data,0) -eq 0x5a4d) {
                if ($data.Length -lt 64) { throw "Incomplete PE header: $($item.FullName)" }
                $offset = [BitConverter]::ToInt32($data,60)
                if ($offset -lt 64 -or $offset -gt $data.Length-6 -or [BitConverter]::ToUInt32($data,$offset) -ne 0x4550) {
                    throw "Invalid PE header: $($item.FullName)"
                }
                $machine = [BitConverter]::ToUInt16($data,$offset+4)
            }
            $hash = (Get-FileHash -LiteralPath $item.FullName -Algorithm SHA256).Hash
            if ($hash.Length -ne $digestSize * 2) { throw 'SHA-256 output disagrees with the digest contract.' }
            $digest = [byte[]]::new($digestSize)
            for ($i=0; $i -lt $digestSize; ++$i) { $digest[$i] = [Convert]::ToByte($hash.Substring($i*2,2),16) }
            $resourceLines += "$id RCDATA ""$($item.FullName.Replace('\','/'))"""
            $flags = 0
            if ($entry.Desktop) { $flags = $flags -bor $constants.kPackageDesktopFlag }
            if ($entry.Product) { $flags = $flags -bor $constants.kPackageProductFlag }
            & $writeRecord $recordFields @{resourceId=$id; flags=$flags; machine=$machine;
                size=$item.Length; nameLength=$entry.Name.Length; digest=$digest}
            $writer.Write([Text.Encoding]::Unicode.GetBytes($entry.Name))
            ++$id
        }
        & $writeRecord $recordFields @{resourceId=0; flags=($constants.kPackageDesktopFlag -bor $constants.kPackageProductFlag);
            machine=0; size=0; nameLength=$names.kInstallerFile.Length; digest=[byte[]]::new($digestSize)}
        $writer.Write([Text.Encoding]::Unicode.GetBytes($names.kInstallerFile))
        $writer.Flush()
        [IO.Directory]::CreateDirectory([IO.Path]::GetDirectoryName($ResourcePath)) | Out-Null
        $resourceLines += "$($constants.kPackageManifestResourceId) RCDATA ""$($ManifestPath.Replace('\','/'))"""
        [IO.File]::WriteAllLines($ResourcePath,$resourceLines,[Text.UTF8Encoding]::new($false))
        [IO.File]::WriteAllBytes($ManifestPath,$memory.ToArray())

    } finally { $writer.Dispose(); $memory.Dispose() }
}


if ($MyInvocation.InvocationName -ne '.') {
    if ($PackageVersion) {
        Write-EmbeddedPackage -Version $PackageVersion -ResourcePath $PackageResourcePath -ManifestPath $PackageManifestPath -DesktopFileList $DesktopFileList -Files $PackageFiles
    } else {
        Get-NativeWindowsArchitecture
    }
}
