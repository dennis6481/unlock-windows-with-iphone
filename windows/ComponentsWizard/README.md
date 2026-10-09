<!-- Created by Rui MA on 28 Sep 2026 -->

# Installer and maintenance

The native Components Wizard installs, updates, reinstalls and removes the four Windows product components. It handles restart continuation and finalization. Authentication and BLE contracts remain outside the installer.

## Package and deployment

The build produces a self-contained `windows/dist/UnlockWithIPhone_<version>_<architecture>_setup.exe` with `x64` or `arm64` as the compiler target architecture suffix; the version is read automatically from [ProductVersion.h](../ProductVersion.h). The service, CP DLL and desktop app are embedded as resources after their builds complete. Component changes regenerate the resource and SHA-256 manifest and rebuild setup. The installed/staged maintenance program is named `setup.exe` and retains the embedded payload. Fixed component names are defined in [ComponentFiles.h](../ComponentFiles.h).

The desktop uses official Windows App SDK self-contained output and Hybrid CRT; authentication components and setup retain their runtime policy. The revised build integration, package generation, final linking and clean-machine operation remain unverified.

| Location | Contents |
|---|---|
| Native System32 | Credential Provider DLL and LocalSystem service. |
| Program Files / Unlock Windows with iPhone | `UnlockWithIPhone.exe`, its self-contained runtime files and `setup.exe`. |
| ProgramData / UnlockWindowsWithIPhone / Setup / Transactions | Protected staging for active transactions only. |
| Windows Settings → Apps | One product entry, version and uninstall command. |

Setup requests UAC and binds installation to the actual physical-console user, even if another administrator supplies elevation. The service starts automatically as LocalSystem. The tray starts normally through that user's Run entry; the installer does not override a user's startup-disable choice. Login startup passes the shared `--background` argument. Install/update creates a shortcut in the all-users Start Menu that opens the main window; uninstall removes it.

Project binaries must match the native OS architecture and product version. Third-party PE machine types are checked against their generated manifest entries, including metadata and resource files. Protected directories require appropriate owner/ACL checks; unsafe paths and reparse points are rejected. Missing or mixed file versions are errors, not guessed installation state.

Before writing a transaction, setup validates its own version/architecture and hashes each embedded component against the build-generated version/architecture manifest. During protected staging it extracts project components and self-contained desktop dependencies, copies itself as `setup.exe` and verifies each file before setting `payloadReady`. Project versions must match; vendor versions are retained. The installer copy is checked against its validated source by size and SHA-256. The hashes detect payload corruption; they are not publisher signatures. There is no adjacent-file fallback or extra extraction directory.

Preflight and preparation use the same package validator. Preparation keeps that validated resource mapping open and extracts its verified bytes without a second resource hash. Installed-package format is checked with installed versions; pending-package format is checked when reading the pending transaction. Project names remain in `ComponentFiles.h`, product version in `ProductVersion.h`, and packed little-endian manifest layout in `PackageManifest.h`. The generator reads every header/record field and the shared SHA-256 digest type; unsupported fields and missing values are errors. The manifest records relative paths, sizes, SHA-256 and each PE machine type; installation, verification, replacement and removal read it. Installed-version verification reads the resident package manifest.

Setup requires Windows 10 1809 or later. Desktop runtime files stay in the app directory; authentication components retain their system paths. Package generation, final linking and clean-environment deployment for this change remain unverified.

## Version and data rules

| Operation | Behavior |
|---|---|
| Install | Confirm and deploy a new complete installation. |
| Update | Higher version; preserve password, registration and ComputerId. |
| Reinstall | Same version, explicitly confirmed; preserve those records. |
| Downgrade | Rejected. |
| Uninstall | Confirm, clear password through the service, remove registration/ComputerId and Windows components/integration. |

The current installation schema is **5**, defined in [SetupContract.h](SetupContract.h). Unsupported schemas, incomplete installations and mismatched pending transactions are rejected. This tool does not migrate them; remove them with their own maintenance tool before a fresh installation. Phone records/private keys are managed separately on the iPhone.

Version 0.1.0 installations and pending transactions must be completed and uninstalled with their original installer before using this package. Missing dependency manifests are rejected; no migration path is retained. Uninstall removes Windows credentials and pairing records, so a fresh installation requires configuration again.

UAC cancellation and confirmation cancellation do not begin the operation. Uninstall from Settings passes `--uninstall` and opens confirmation with Cancel as default. An active transaction takes precedence over starting another operation.

## Transaction and completion boundaries

The installer re-queries state before acting. It persists transaction ownership and target paths before creating/writing staging. Preparation failure keeps its ownership and error evidence; continuation remains tied to that same transaction.

Update/removal remove Run, identify all instances by the installed main-app path, verify the tray user/session and request normal exit. Each retained instance is waited on for 30 seconds; an active/new instance pauses maintenance rather than being killed or considered released. Update disables CP/stops the service, crosses a real restart boundary, replaces and verifies files, then restores the service, CP and Run.

Deployment and exit finalization are separate. Formal installation records, active transaction state and non-secret result snapshots have distinct roles. Shared schema, registry names, stages, task/event/mutex names and snapshot layout come from SetupContract.h; C++ and generated in-memory PowerShell consume that source.

- A SYSTEM completion task runs the protected staged installer for the current transaction.
- A serialized SYSTEM finalizer uses short-lived Windows PowerShell, waits for the verified continuation process and holds the maintenance mutex. Generated commands enforce a 32,000-character limit.
- Deletion is limited to the transaction's known files and empty directories. Unknown contents, unsafe ACLs, reparse points and deletion errors prevent a success claim.
- Install/update finalization releases staging before launching the ordinary target user's result page. A fresh install offers **Start setup** and **Later**, reusing existing page controls. Start setup hands off to the ordinary tray; either choice acknowledges the one-time installation result. Update/reinstall keep the normal **Finish** result and do not automatically repeat configuration.
- The observer derives the first-install handoff from the existing transaction operation. It passes an internal setup argument to the verified result UI; no persisted installation or completion schema is added. Setup progress comes from credential and enrollment records.
- Uninstall copies a non-secret result into the target-user process, signals a transaction/user-bound acknowledgment event, then finishes SYSTEM cleanup. The event conveys receipt, not paths or authentication authority; its owner/ACL are checked.
- With the target user absent, result handoff remains pending until sign-in. Starting a task, scheduling deletion or deleting components alone is not full completion.

File replacement verifies staging and prepares all `.update` files before replacing targets. Obsolete dependencies are removed before the resident installer is replaced last. Failure preserves staging and transaction diagnostics; continuation repeats verification and replacement without automatic rollback. The Settings entry may temporarily refer to protected staging or a constrained PowerShell continuation while its normal EXE is being released. Finish only after the final result, and use the maintained continuation entry for an incomplete transaction.

File removal is not physical erasure of SSD, backup or snapshot history. See [SECURITY.md](../../SECURITY.md).

## UI and diagnostics

The wizard uses themed Win32 controls, PerMonitorV2 layout, Task Dialog confirmations/errors and a scrollable operation log. Execution disallows cancel/close; Restart now / Later preserves the restart state as appropriate. UI display failure is distinct from the transaction result.

[Get-ComponentsStatus.ps1](../Diagnostics/Get-ComponentsStatus.ps1) reads shared definitions and reports component architecture/version/hash, installation/transaction/result records and related tasks. It separates absent records from read failures. It does not run tasks, mount offline hives or repair state.

Use the [installer test matrix](../../docs/Testing.md#installer-and-removal) for versions, restarts, cancellation, failure, result handoff and complete removal. Tests must check the actual final state, not just whether the app entry disappeared.

## References

- [Windows Run entries](https://learn.microsoft.com/en-us/windows/win32/setupapi/run-and-runonce-registry-keys)
- [Uninstall registry values](https://learn.microsoft.com/en-us/windows/win32/msi/uninstall-registry-key)
- [Task Scheduler schema](https://learn.microsoft.com/en-us/windows/win32/taskschd/task-scheduler-schema)
- [TaskDialog and Common Controls v6](https://learn.microsoft.com/en-us/windows/win32/api/commctrl/nf-commctrl-taskdialog)
