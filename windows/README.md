<!-- Created by Rui MA on 26 Sep 2026 -->

# Windows developer guide

The Windows side contains four installed components: the desktop app, LocalSystem credential service, Credential Provider DLL and maintenance installer. [PROTOCOL.md](../PROTOCOL.md) defines authentication; [SECURITY.md](../SECURITY.md) explains credential protection.

## Compatibility

- **Windows:** Windows 10 version 1809, build 17763, or later, including Windows 11. The minimum is based on API requirements and has not been tested on that build.
- **Architecture:** Native x64 or ARM64; all components must match the OS architecture. ARM64 has not been tested on physical hardware. 32-bit x86 and ARM32 are not supported.
- **Bluetooth:** The adapter and driver must support BLE Central, protected GATT and advertisement scanning.

## Build prerequisites

- Windows and Visual Studio 2022 / 2026 or matching Build Tools with **Desktop development with C++**, **C++ WinUI app development tools**, MSVC C++20 support and the target architecture's tools. The WinUI tools supply native XAML MSBuild targets. ARM64 requires the ARM64 C++ tools component.
- Windows SDK **10.0.22621.0 or newer** with C++/WinRT headers and `cppwinrt.exe`; a recent SDK is recommended. The C++/WinRT NuGet package supplies the MSBuild integration.
- **GNU Make** available on `PATH`, plus the Visual Studio `MSBuild.exe` and Windows SDK tools supplied by the installation above. `make` remains the public entry point; it invokes the checked-in MSBuild solution and projects directly.
- Run from a native Windows PowerShell or command prompt. The Makefile uses Windows commands and is not a WSL build workflow.

From the repository root:

```powershell
make -C windows build
make -C windows test
make -C windows build-release
```

`test` builds first and then runs the four native test programs in their existing order. `make -C windows` builds and runs tests; `build-release` builds Release targets without executing them. The shared [WindowsBuild.ps1](WindowsBuild.ps1) helper finds Visual Studio with `vswhere`, selects native `x64` or `arm64`, initializes the MSBuild environment and validates the Windows SDK tools. It redirects compiler temporary files into the ignored root `.tmp/` directory.

To select a target and separate build directories explicitly:

```powershell
make -C windows build-release TARGET_ARCH=x64 BUILD_DIR=build/x64-release
make -C windows build-release TARGET_ARCH=arm64 BUILD_DIR=build/arm64-release
```


The installer is generated at `windows/dist/UnlockWithIPhone_<version>_<architecture>_setup.exe`, with `x64` or `arm64` matching the compiler target and the version read from [ProductVersion.h](ProductVersion.h). Distribute only the **Release** setup EXE; it embeds the desktop app and its runtime files, service and Credential Provider. Static libraries are isolated under `lib/<architecture>/<configuration>` to prevent Debug/Release runtime mixing. Use separate build directories per architecture/configuration; the active desktop EXE remains at the build root for existing make commands.

The desktop build follows make → MSBuild Solution/.vcxproj. Native libraries, the service, Credential Provider, desktop WinUI app and installer are separate projects with explicit dependencies and outputs. Pinned Windows App SDK packages and Hybrid CRT remain in use; local NuGet caches and Visual Studio user settings are ignored by Git. XAML generation and `DesktopApp.files` preserve the pages' relative directories. `DesktopApp.files` comes from the WinUI project; packaging embeds one dependency manifest for paths, sizes, SHA-256 and PE machine types. Third-party files retain their versions. The presence replacement built successfully for x64 Release on 11 Oct 2026 with tests disabled (0 errors, 0 warnings). Local resource limits required one MSBuild node and one compiler process. Tests, runtime, clean-machine deployment and ARM64 acceptance remain pending.

## Install and configure

For installation and setup, see the [main guide](../README.md#installation).

Open **Unlock with iPhone** from the Start Menu to show the main window. Install/update creates the all-users shortcut; uninstall removes it.

- Save your Microsoft account password, not your PIN. Update the saved copy whenever the account password changes; see [password management](SavedCredential/README.md#password-management).
- Remove the paired iPhone on **Status**, or delete the saved password on **Password**; these are separate actions.

## Update and uninstall

Run a newer installer to **Update**, or the same version to **Reinstall**. Downgrades are rejected. Updates preserve your saved password and pairing information.

For uninstall instructions, see the [main guide](../README.md#uninstall). For installation compatibility and failure recovery, see the [installer guide](Setup/README.md).

## Troubleshooting

Use tray **Status… → Diagnostics** and the [testing guide](../docs/Testing.md#diagnostics). From the repository root, the read-only component inspector is:

```powershell
& '.\windows\Diagnostics\Get-ComponentsStatus.ps1'
```

It does not start services/tasks, repair installations or mount offline user hives. Do not run a second build-tree tray alongside the installed app. A service approved status does not confirm that Windows accepted the password.

## Module index

The [system BLE diagnostic](../docs/BleSystemPoc.md#localsystem--session-0-prerequisite) uses a separate `SystemBleDiagnostic` target and shared `Bluetooth` definitions. It is not installed or built with the product and cannot unlock Windows.

```text
windows/
├── Bluetooth/          Shared system pairing relationship and service BLE operations.
├── SystemBleDiagnostic/ Standalone diagnostic, never installed.
├── DesktopApp/         MSBuild desktop EXE, role dispatch, WinUI and Win32 TrayManager.
├── Enrollment/         Ordinary-user system pairing UI, UAC helper and protected binding store.
├── SavedCredential/    Credential service, IPC, encrypted password storage and management UI.
├── CredentialProvider/ Windows sign-in tile and native credential submission.
├── Protocol/           SHA-256 hashing for installer package integrity.
├── Setup/              Installation, updates, removal and restart continuation.
├── Resources/          Win32 appearance, manifests, icons and version resources.
├── *Tests/             C++ regression tests orchestrated by UnlockWindowsTests.proj.
└── Diagnostics/        Read-only component and installation-state inspection.
```

Module guides: [SavedCredential](SavedCredential/README.md), [CredentialProvider](CredentialProvider/README.md) and [Setup](Setup/README.md). See [PROTOCOL.md](../PROTOCOL.md) for the shared protocol.

## Desktop app roles

| Arguments | Role |
|---|---|
| None | Ordinary-user tray and WinUI main window; repeated launch activates it. Elevated execution is rejected. |
| `--background` | Login startup without opening the main window; repeated launch leaves an existing window unchanged. |
| `--saved-password` | Temporary elevated password-management window. |
| `--saved-password --save`, `--saved-password --update`, `--saved-password --remove` | Internal operation-specific elevated WinUI password window. |
| `--setup` | Ordinary-user setup request handled by the existing single-instance tray. |
| `--saved-password --setup` | Internal elevated password step; an explicit readiness result permits the ordinary tray to continue on Status. |
| `--binding-helper <operation> <encoded-request>` | Internal temporary elevated service-management helper; not a public command. |

The main WinUI window and tray retain the desktop STA. A desktop worker handles helpers/status; the LocalSystem service's single MTA worker owns BLE validation. Closing the main window hides it; Quit exits the desktop app without disabling lock-screen verification. Role arguments do not grant service permission.

Navigation remains **Status**, **Password**, **Diagnostics**, with **About** at the bottom. Switching pages uses the native WinUI upward entrance/fade transition. Password management, notifications and update checks retain their existing roles. All pages share an outer scroller for headers, actions and content, with per-page positions. Diagnostics preserves text selection/scrolling and no longer embeds BLE probe code.

**Status** shows pairing guidance and a paired-device list when no iPhone is bound. Open Windows Bluetooth settings to pair, return, select a device and click **Bind selected device**. Binding/removal require confirmation and UAC. A bound iPhone keeps its existing status layout with removal only; remove it before binding another. The WinUI removal confirmation defaults to Cancel; successful removal returns to device selection and keeps Windows pairing and the saved password. Paired Classic/BLE entries share one row per valid ContainerId, showing only the device name. There is no separate binding window.

The main window uses system Mica and theme colors across the WinUI title bar, sidebar and page background; Windows 10 uses the framework's solid backdrop. The minimum window width is 800 effective pixels. Pages have no outer panel and fill the available width up to a centered 800 effective pixels. The sidebar uses native Auto layout without a manual toggle button. **Status** uses icon cards for **Last approval**, **Signal threshold** and **Remove bound iPhone**. Devices update automatically and on activation. Dragging edits a pending value; the right-side **Save** requests UAC. Refusal/failure restores the saved value and shows the reason. **Initial signal threshold** uses the same range/default, with binding below it. Only confirmation dialogs show Cancel; app-shutdown cancellation remains. No hardware acceptance is claimed.
## Tag builds

Windows installers are automatically built and published when a version tag is pushed. CI prepares build resources and invokes the MSBuild solution through `WindowsBuild.ps1`, without requiring GNU Make. See the [Release workflow](../.github/workflows/release.yml).

## References

- [Windows device pairing](https://learn.microsoft.com/en-us/windows/uwp/devices-sensors/pair-devices)
- [Windows App SDK self-contained deployment](https://learn.microsoft.com/en-us/windows/apps/package-and-deploy/self-contained-deploy/deploy-self-contained-apps)
- [GetDpiForWindow requirements](https://learn.microsoft.com/en-us/windows/win32/api/winuser/nf-winuser-getdpiforwindow)
- [Bluetooth GATT client](https://learn.microsoft.com/en-us/windows/uwp/devices-sensors/gatt-client)
