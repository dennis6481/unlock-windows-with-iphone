# Windows Installer

The self-contained x64 and ARM64 MSI packages use standard Windows installation and maintenance dialogs. Installation is per machine at fixed locations; no EXE bootstrapper or target-machine .NET runtime is required.

## Package and version

- [WiX SDK and UI extension](../Msi/UnlockWindows.wixproj) are pinned to **7.0.1**. The existing make/MSBuild entry builds native components, generates WiX sources and builds the MSI.
- [ProductVersion.h](../ProductVersion.h) owns the four-part version. Generation checks MSI ranges: major/minor <= 255, patch <= 65535. No field is truncated.
- MSI ProductVersion uses the first three parts; `FullProductVersion` and product file versions retain all four. `.23 → .24` updates, `.24 → .24` reinstalls and `.24 → .23` is rejected in the execute sequence, including silent installation.
- Each architecture has a fixed UpgradeCode; new packages receive new ProductCode/PackageCode values. Running the same package opens maintenance. Repair uses `REINSTALLMODE=amus` to replace equal-version files.
- Major upgrades remove the old MSI after InstallInitialize, inside the rollback transaction. Upgrade removal never clears credentials or binding.
- Output: `dist/UnlockWithIPhone_<major.minor.patch>_<x64|arm64>_setup.msi`. Snapshot artifact names retain `SNAPSHOT(<build>)`.

Payload filenames come from [ComponentFiles.h](../ComponentFiles.h); desktop/runtime files come from `DesktopApp.files`. MSI manages files, service registration, CP registration, the all-users shortcut and its own uninstall registration. Third-party files retain their own versions.

The all-users Start Menu shortcut is advertised and belongs to the main executable's component. Repair restores it through that component.

## EXE takeover

Only complete **schema 5** installations are supported. The reader checks four-part version, native architecture, target SID, installed components, embedded dependency hashes, service/CP registration and maintenance entry before mutation. Old transactions, pending result/continuation tasks, inconsistent state and older formats are rejected; complete or remove them with the original installer.

Takeover preserves password, binding and configured user. It never calls `setup.exe --uninstall`. A protected snapshot contains only deployment files, shortcut, service configuration and non-sensitive registry registration. MSI owns file removal/replacement, including occupied-file reboot scheduling; the native rollback restores the snapshot and original maintenance entry on failure. Restoration of occupied files can itself require restart. Recovery errors retain the snapshot and report failure.

After successful commit, the old EXE, uninstall entry and superseded schema fields are removed. The schema 5 module only reads old installations; the old deployment engine, PowerShell finalizer, result events and SYSTEM continuation tasks are not shipped.

## Identity and user interaction

[ProductIdentity.h](../ProductIdentity.h) defines the durable configured SID at the existing `InstalledProduct\TargetSid` location for MSI, service and CP. First installation selects the physical-console user. Migration, upgrade and repair retain that user, including when another administrator supplies elevation.

First installation writes a non-sensitive one-time marker in that user's profile. The ordinary app shows **Start setup / Later**, clearing the marker after either choice. Updates and repairs do not recreate it or change an existing login-startup choice.

On commit without pending replacement, MSI starts the app with the target user's ordinary token when that console session is available. Otherwise it waits for normal login startup or manual launch. Launch errors are reported separately from committed deployment; MSI does not wait for the user to acknowledge setup.

## Restart and removal

A short-lived native DLL host runs the existing normal-exit request in the target user session; the installer does not kill the app or LogonUI. A maintenance marker blocks app startup during deployment; takeover temporarily retires the old app entry, with snapshot restoration on rollback. MSI handles occupied-file replacement and reports a required restart. Pending replacement blocks service/app startup before restart; afterward the automatic service and normal user startup apply.

Active uninstall requires the configured physical-console user to be signed in and unlocked and the credential service to be running. Before stopping the service, MSI requires `clearForRemoval` acknowledgment for password, binding and active authorization deletion. The removal-only SYSTEM MSI identity cannot invoke other management operations or bypass lock restrictions.

Credential deletion is irreversible. Later removal failure reports that fact; rollback restores deployment resources, not deleted credentials. Windows Bluetooth pairing and the Windows account password are unchanged. See [SECURITY.md](../../SECURITY.md).

## Verification

CI retains the native test gate and checks MSI properties, architecture, lifecycle-action conditions and embedded cabinets before artifact upload. It extracts cabinets as data, compares the actual payload with the authoritative file lists and checks PE architecture and four-part product versions. PE checks distinguish native code, resource/metadata containers and ARM64X runtime binaries; product components must match the target architecture.

ICE03 is excluded because it rejects WinUI language resources and DLL language lists. Package checks compare file language metadata with the extracted payload and validate its language IDs; other ICE checks remain enabled.

Use recoverable x64/ARM64 test machines for first installation, complete schema 5 takeover, injected failure/rollback, same-version repair, fourth-part upgrade/downgrade, active versus upgrade removal, locked-console rejection, absent target user, alternate administrator elevation and disabled startup. Check occupied files, postponed restart and post-restart component consistency on the minimum supported and current Windows versions. Record BLE and native unlock separately from package checks.

References: [WiX release notes](https://docs.firegiant.com/wix/whatsnew/releasenotes/), [major upgrades](https://docs.firegiant.com/wix/schema/wxs/majorupgrade/).
