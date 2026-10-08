<!-- Created by Rui MA on 26 Sep 2026 -->

# Windows developer guide

The Windows side contains four installed components: the desktop app, LocalSystem credential service, Credential Provider DLL and maintenance installer. [PROTOCOL.md](../PROTOCOL.md) defines authentication; [SECURITY.md](../SECURITY.md) explains credential protection.

## Compatibility

- **Windows:** Windows 10 version 1703, build 15063, or later, including Windows 11. The minimum is based on API requirements and has not been tested on that build.
- **Architecture:** Native x64 or ARM64; all components must match the OS architecture. ARM64 has not been tested on physical hardware. 32-bit x86 and ARM32 are not supported.
- **Bluetooth:** The adapter and driver must support BLE GATT server / peripheral advertising.

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


The installer is generated at `windows/dist/UnlockWithIPhone_<version>_<architecture>_setup.exe`, with `x64` or `arm64` matching the compiler target and the version read from [ProductVersion.h](ProductVersion.h). Distribute only the **Release** setup EXE; it embeds the desktop app, service and Credential Provider. Debug and Release share the same output path.

Release statically links the MSVC runtime to avoid requiring a separate VC++ Redistributable. Packaging verifies component versions and architectures and generates SHA-256 hashes. Dependency inspection and clean-machine installation/runtime validation remain pending.

## Install and configure

For installation and setup, see the [main guide](../README.md#installation).

- Save your Microsoft account password, not your PIN. Update the saved copy whenever the account password changes; see [password management](SavedCredential/README.md#password-management).
- Removing the paired iPhone and deleting the saved password are separate tray actions.

## Update and uninstall

Run a newer installer to **Update**, or the same version to **Reinstall**. Downgrades are rejected. Updates preserve your saved password and pairing information.

For uninstall instructions, see the [main guide](../README.md#uninstall). For installation compatibility and failure recovery, see the [installer guide](ComponentsWizard/README.md).

## Troubleshooting

Use tray **Status… → Technical details**, iOS Settings → Diagnostics and the [testing guide](../docs/Testing.md#diagnostics). From the repository root, the read-only component inspector is:

```powershell
& '.\windows\Diagnostics\Get-ComponentsStatus.ps1'
```

It does not start services/tasks, repair installations or mount offline user hives. Do not run a second build-tree tray alongside the installed app. An approval status on the phone does not confirm that Windows accepted the password.

## Module index

```text
windows/
├── DesktopApp/         Main EXE entry point and role dispatch.
├── GattHost/           Tray, lock-aware advertising, BLE and pairing transport.
├── Enrollment/         Elevated enrollment and fingerprint confirmation.
├── SavedCredential/    Credential service, IPC, encrypted password storage and management UI.
├── CredentialProvider/ Windows sign-in tile and native credential submission.
├── PhoneApproval/      Challenge verification and protected registration storage.
├── Protocol/           Signing payload, hashing and signature verification.
├── ComponentsWizard/   Installation, updates, removal and restart continuation.
├── Resources/          Win32 appearance, manifests, icons and version resources.
├── *Tests/             C++ regression tests registered with CTest.
└── Diagnostics/        Read-only component and installation-state inspection.
```

Module guides: [GattHost](GattHost/README.md), [SavedCredential](SavedCredential/README.md), [CredentialProvider](CredentialProvider/README.md) and [ComponentsWizard](ComponentsWizard/README.md). See [PROTOCOL.md](../PROTOCOL.md) for the shared protocol.

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

## Tag builds

Windows installers are automatically built and published when a version tag is pushed. See the [Release workflow](../.github/workflows/release.yml).

## References

- [GattServiceProvider requirements](https://learn.microsoft.com/en-us/uwp/api/windows.devices.bluetooth.genericattributeprofile.gattserviceprovider)
- [PerMonitorV2 and Windows 10 1703](https://blogs.windows.com/windowsdeveloper/2017/04/04/high-dpi-scaling-improvements-desktop-applications-windows-10-creators-update/)
- [GetDpiForWindow requirements](https://learn.microsoft.com/en-us/windows/win32/api/winuser/nf-winuser-getdpiforwindow)
- [Advertisement enum version history](https://learn.microsoft.com/en-us/uwp/api/windows.devices.bluetooth.genericattributeprofile.gattserviceprovideradvertisementstatus)
