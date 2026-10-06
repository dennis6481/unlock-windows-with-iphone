<!-- Created by Rui MA on 26 Sep 2026 -->

# Windows developer guide

The Windows side contains four installed components: the desktop app, LocalSystem credential service, Credential Provider DLL and maintenance installer. [Protocol.md](../Protocol.md) defines authentication; [SECURITY.md](../SECURITY.md) explains credential protection.

## Compatibility

The API-derived runtime minimum is **Windows 10 version 1703 (Creators Update), build 15063**. Windows 11 is also within the intended OS range. This minimum is inferred from the current API usage, not from an oldest-build device test.

| Source dependency | Runtime floor / build requirement |
|---|---|
| `GattServiceProvider`, local characteristics, subscribed clients and sessions in `GattHost` | Windows 10 1703, build 15063, Universal API Contract v4. |
| Desktop `PerMonitorV2` manifests | Windows 10 1703, build 15063. |
| `GetDpiForWindow`, `GetSystemMetricsForDpi` and `SetThreadDpiAwarenessContext` | Windows 10 1607; covered by the 1703 floor. |
| `StartedWithoutAllAdvertisementData` enum constant | Windows SDK 10.0.18362.0 or newer for compilation. The code compares an enum value; it does not call a new 1903-only method. |

The manifests declare desktop privileges and DPI awareness; CMake does not pin an exact SDK version or Windows build. Use a recent Windows SDK containing C++/WinRT headers. OS eligibility does not guarantee a working adapter: the PC must support **BLE GATT server / peripheral advertising**, including driver support.

The build helper and installer recognize **x64 and ARM64** only. All components must match the native OS architecture; emulated x64 binaries are not the ARM64 deployment. ARM64 is an intended build target and has not been validated on physical hardware. Neither 32-bit x86 nor ARM32 is supported.

## Build prerequisites

- Windows and Visual Studio 2022 / Build Tools 2022 with **Desktop development with C++**, MSVC C++20 support and the target architecture's tools. ARM64 requires the ARM64 C++ tools component.
- Windows SDK **10.0.18362.0 or newer** with C++/WinRT headers; a recent SDK is recommended.
- **CMake 3.25 or newer**, `ctest`, and **GNU Make** available on `PATH`. `make` here is GNU Make; the CMake generator uses the separate MSVC `nmake` supplied by Visual Studio.
- Run from a native Windows PowerShell or command prompt. The Makefile uses Windows commands and is not a WSL build workflow.

From the repository root:

```powershell
make -C windows build
make -C windows test
make -C windows build-release
```

`test` builds first. `make -C windows` builds and runs tests; `build-release` builds Release targets without executing them. The helper finds Visual Studio with `vswhere`, selects native `x64` or `arm64`, and configures CMake with `NMake Makefiles`. It redirects compiler temporary files into the ignored root `.tmp/` directory.

To select a target and separate build directories explicitly:

```powershell
make -C windows build-release TARGET_ARCH=x64 BUILD_DIR=build/x64
make -C windows build-release TARGET_ARCH=arm64 BUILD_DIR=build/arm64
```

Use separate directories when changing architecture or configuration. For a nonstandard Visual Studio location, pass `VS_DEV_CMD=<absolute-path-to-VsDevCmd.bat>` as a quoted Make argument. The helper still selects the requested architecture.

The build directory contains `UnlockWithIPhone.exe`, `unlock_saved_credential_service.exe`, `unlock_credential_provider.dll`, test binaries and intermediate files. The installer is written separately to `windows/dist/UnlockWithIPhone_<version>_setup.exe`; its debugging symbols remain in the build directory. The version comes from [ProductVersion.h](ProductVersion.h); the distribution directory and installer naming rule come from [CMakeLists.txt](CMakeLists.txt), with fixed component names in [ComponentFiles.h](ComponentFiles.h). Distribute only the setup EXE: it embeds the other three components from the same build. The default build selects the current native architecture; no second architecture build is required. Debug and Release use the same setup filename/directory; distribute the result of a Release build.

CMake statically links the MSVC runtime (`/MT` for Release, `/MTd` for Debug). Release packaging is intended to run without Visual Studio, CMake or a separately installed VC++ Redistributable. The build checks embedded component versions/architecture and generates their SHA-256 manifest before linking setup. These source changes have only been statically checked; Release import inspection and clean-machine installation/runtime acceptance are pending. Debug output is not the distribution artifact.

## Install and configure

1. Build Windows and iOS from matching revisions. Keep a working native Windows password/PIN available.
2. Sign in to the target Microsoft Account at the physical console and run the versioned setup EXE; companion files are not needed. Setup requests UAC itself; follow its confirmation and restart instructions.
3. After restart, sign in once with your usual native PIN/password. The service starts as LocalSystem; the ordinary-user tray starts through the target user's Run entry.
4. On the verified installation result page choose **Start setup**, or choose **Later** and use tray **Continue setup…**. The existing password window requests UAC and verifies the installed target account without an additional lock/sign-in cycle. Save the actual MSA password, not the PIN. This stores a local copy; it does not change the account password. See [password management](SavedCredential/README.md#password-management).
5. After the service confirms the saved copy, setup opens the existing pairing window. Allow UAC, choose **Add a Windows PC** and then **Continue** in the iOS app, and confirm the account and full fingerprint. Already completed steps are skipped; cancelled or failed password management cannot advance to pairing. See [pairing](GattHost/README.md#pairing).
6. Lock Windows, select the phone tile and press **Enter / Unlock** once. With a sufficient fresh RSSI reading, the phone signs and Windows attempts native authentication.

Starting Windows, signing out, or having no existing console session does not offer phone sign-in. Changing the online MSA password requires updating the saved copy. Removing phone registration does not remove the saved password; both have separate tray actions.

## Update and uninstall

Run a higher-version package for **Update** or the same version for explicit **Reinstall**; downgrades are rejected. Updates preserve the password copy, phone registration and ComputerId. Follow the restart boundary and finish the result page.

Older companion-file installations and their pending transactions are not supported by the self-contained installer. Complete any pending operation and uninstall using that installation's original maintenance tool before a fresh installation. No migration or companion-file fallback is provided.

Use Windows Settings → Apps to uninstall. Removal clears the local password copy, phone registration, target user's ComputerId, product files and integration records. Delete the computer record on the iPhone separately. Details and failure recovery are in the [installer guide](ComponentsWizard/README.md).

Only the current complete installation and installation schema can be maintained. Unsupported or incomplete installations are rejected rather than guessed, migrated or silently repaired. Use the maintenance tool belonging to such an installation to remove it before a fresh install.

## Desktop app roles

| Arguments | Role |
|---|---|
| None | Ordinary-user single-instance tray, BLE and session monitoring; elevated execution is rejected. |
| `--saved-password` | Temporary elevated password-management window. |
| `--setup` | Ordinary-user setup request handled by the existing single-instance tray. |
| `--saved-password --setup` | Internal elevated password step; an explicit readiness result permits the ordinary tray to continue to pairing. |
| `--bluetooth` plus internal arguments | Temporary elevated pairing/removal role, launched by the tray. Not a public manual command. |
| `--key-hex <public-key> [--replace]`, `--key-clipboard [--replace]`, `--clear` | Elevated manual public-key enrollment using the calling console. |

Closing an operation window does not exit the tray. Role parsing is defined in [DesktopApp.h](DesktopApp/DesktopApp.h); role arguments do not grant permission.

For manual enrollment, use an elevated PowerShell console on the unlocked target desktop, place the phone's 65-byte uncompressed P-256 public key as 130 hexadecimal digits on the clipboard, then run:

```powershell
$app = (Resolve-Path '.\windows\build\UnlockWithIPhone.exe').Path
$process = Start-Process -FilePath $app -ArgumentList '--key-clipboard' -NoNewWindow -Wait -PassThru
$process.ExitCode
```

Manual enrollment still requires fingerprint confirmation; replacement requires `--replace`, and clear requires explicit removal confirmation. It does not start BLE or provide an authentication bypass.

## Module index

| Directory | Responsibility |
|---|---|
| `DesktopApp` | Main EXE entry point and role dispatch. |
| [GattHost](GattHost/README.md) | Ordinary-user tray, lock-aware advertising, BLE and pairing transport. |
| `Enrollment` | Elevated enrollment, fingerprint confirmation and atomic registration writes. |
| [SavedCredential](SavedCredential/README.md) | Service authority, restricted IPC, encrypted password storage and management UI. |
| [CredentialProvider](CredentialProvider/README.md) | LogonUI tile, system identity capture and native credential submission. |
| `PhoneApproval` | Challenge/signature verification and protected registration storage, consumed by the service and enrollment code. |
| `Protocol` | Canonical signing payload and shared CNG hashing, fingerprints and verification; see [Protocol.md](../Protocol.md). |
| [ComponentsWizard](ComponentsWizard/README.md) | Install/update/removal decisions, deployment, reboot continuation and finalization. |
| `Resources` | Shared Win32 appearance, manifests and embedded icon/version resources. |
| `*Tests` | C++ regression tests registered with CTest. |
| `Diagnostics` | Read-only component and installation-state inspection. |

## Troubleshooting

Use tray **Status… → Technical details**, iOS About → Diagnostics and the [testing guide](../docs/Testing.md#diagnostics). From the repository root, the read-only component inspector is:

```powershell
& '.\windows\Diagnostics\Get-ComponentsStatus.ps1'
```

It does not start services/tasks, repair installations or mount offline user hives. Do not run a second build-tree tray alongside the installed app. An approval status on the phone does not confirm that Windows accepted the password.

## Compatibility references

- [GattServiceProvider requirements](https://learn.microsoft.com/en-us/uwp/api/windows.devices.bluetooth.genericattributeprofile.gattserviceprovider)
- [PerMonitorV2 and Windows 10 1703](https://blogs.windows.com/windowsdeveloper/2017/04/04/high-dpi-scaling-improvements-desktop-applications-windows-10-creators-update/)
- [GetDpiForWindow requirements](https://learn.microsoft.com/en-us/windows/win32/api/winuser/nf-winuser-getdpiforwindow)
- [Advertisement enum version history](https://learn.microsoft.com/en-us/uwp/api/windows.devices.bluetooth.genericattributeprofile.gattserviceprovideradvertisementstatus)
