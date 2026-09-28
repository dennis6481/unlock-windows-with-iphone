REM Created by Rui MA on 28 Sep 2026
@echo off
setlocal EnableExtensions EnableDelayedExpansion

if not defined UNLOCK_VS_DEV_CMD (
    echo UNLOCK_VS_DEV_CMD is required. 1>&2
    exit /b 2
)

if not defined UNLOCK_CMAKE_COMMAND (
    echo UNLOCK_CMAKE_COMMAND is required. 1>&2
    exit /b 2
)

if not defined UNLOCK_TARGET_ARCH set "UNLOCK_TARGET_ARCH=auto"

set "CMAKE_COMMAND=%UNLOCK_CMAKE_COMMAND%"
set "REQUESTED_ARCH=%UNLOCK_TARGET_ARCH%"

if /I "%REQUESTED_ARCH%"=="auto" (
    for /f "delims=" %%A in ('powershell.exe -NoProfile -ExecutionPolicy Bypass -File "%~dp0WindowsArchitecture.ps1"') do set "TARGET_ARCH=%%A"
) else (
    set "TARGET_ARCH=%REQUESTED_ARCH%"
)

if /I not "%TARGET_ARCH%"=="x64" if /I not "%TARGET_ARCH%"=="arm64" (
    echo Unsupported target architecture "%TARGET_ARCH%". Use auto, x64, or arm64. 1>&2
    exit /b 2
)

if /I "%UNLOCK_VS_DEV_CMD%"=="auto" (
    if /I "%TARGET_ARCH%"=="arm64" (
        set "REQUIRED_VS_COMPONENT=Microsoft.VisualStudio.Component.VC.Tools.ARM64"
    ) else (
        set "REQUIRED_VS_COMPONENT=Microsoft.VisualStudio.Component.VC.Tools.x86.x64"
    )

    set "VSWHERE=%ProgramFiles(x86)%\Microsoft Visual Studio\Installer\vswhere.exe"
    if exist "!VSWHERE!" (
        for /f "usebackq delims=" %%A in (`"!VSWHERE!" -latest -prerelease -products * -requires !REQUIRED_VS_COMPONENT! -property installationPath`) do set "VS_INSTALLATION=%%A"
    )

    if defined VS_INSTALLATION (
        set "VS_DEV_CMD=!VS_INSTALLATION!\Common7\Tools\VsDevCmd.bat"
    )

    if not defined VS_DEV_CMD if defined VSINSTALLDIR if exist "!VSINSTALLDIR!Common7\Tools\VsDevCmd.bat" (
        set "VS_DEV_CMD=!VSINSTALLDIR!Common7\Tools\VsDevCmd.bat"
        echo Visual Studio C++ component !REQUIRED_VS_COMPONENT! was not found by vswhere; using the active Developer Command Prompt. 1>&2
    )

    if not defined VS_DEV_CMD (
        echo Could not find a Visual Studio installation with !REQUIRED_VS_COMPONENT!. 1>&2
        echo Install Desktop development with C++ and the native %TARGET_ARCH% MSVC build tools, then rerun make. 1>&2
        echo To use a nonstandard installation, pass VS_DEV_CMD=full\path\to\VsDevCmd.bat to make. 1>&2
        exit /b 2
    )
) else (
    set "VS_DEV_CMD=%UNLOCK_VS_DEV_CMD%"
)

if not exist "%VS_DEV_CMD%" (
    echo VsDevCmd.bat was not found at "%VS_DEV_CMD%". 1>&2
    exit /b 2
)

call "%VS_DEV_CMD%" -arch=%TARGET_ARCH%
if errorlevel 1 exit /b %errorlevel%

echo Building for %TARGET_ARCH%.
"%CMAKE_COMMAND%" %*
exit /b %errorlevel%
