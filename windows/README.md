# Windows implementation

The Windows component test target is Windows 10 or later. The native
Components Wizard is the only normal installation and uninstall entry point.
PowerShell does not copy DLLs, edit component registry values, maintain JSON
backups, or implement a second transaction flow.

## Components Wizard

The wizard is a native Windows EXE with an explicit Common Controls v6 and
requireAdministrator manifest. It uses a classic Wizard97 Property Sheet with
a generated left-side watermark and:

- a status page showing the current state and one safe primary action;
- a confirmation page before installation, removal, or recovery;
- a progress page for the transaction;
- a completion or recovery page with an explicit restart action.

The implementation is split into:

- ComponentState: pure state snapshot and recovery-plan decisions;
- WindowsAdapter: registry, System32, PE architecture, Task Scheduler and UAC
  operations, including saved-credential service control;
- ComponentTransaction: installation, registration removal, post-restart
  cleanup, rollback and stale-state recovery;
- main.cpp: Property Sheet page lifecycle only.

The state record is stored at
HKLM\SOFTWARE\UnlockWindowsWithIPhone\ComponentsWizard. It contains the
schema version, current phase, transaction ID, credential-cleanup status,
wizard path, timestamp and last error. Unknown files or registrations without
a valid transaction record are never deleted automatically.

Installation writes an Installing record before changing the machine and
changes it to Installed only after verification. If rollback cannot finish,
RecoveryRequired is preserved. The current VM wizard installs the Credential
Provider and a LocalSystem saved-credential service; it does not register or
load a custom LSA package. Normal uninstall first confirms deletion of the
saved credential, then removes both registrations, registers an interactive
high-privilege logon task, and deletes the remaining binaries after restart.
The task invokes the internal
resume-uninstall entry point. A failed cleanup keeps state for retry. The
explicit `--emergency-remove` option can remove known components when the
credential cannot be confirmed cleared; it retains `RemovedUnconfirmed` state
and must not be interpreted as secret erasure.

The installer creates System32 binaries directly with normal file attributes and
copies bytes without inheriting source attributes. Windows 10 and later
native x64 or ARM64 builds are accepted; the wizard, source binaries and Windows
architecture must match.

The saved-credential path has been built and installed in a VM. After a fresh
one-test authorization, the Credential Provider used the saved credential
without manual password entry and unlocked the existing SID and console
session. Repeated manager Refresh was stable after the pipe completion,
grant-nonce, and bounded full-reply acknowledgment changes. Refresh reports
the failing IPC stage and Win32 code if a transport failure recurs. Replay
rejection, service-restart persistence, identity-change rejection, and failure
recovery still need separate VM evidence.
See [the manual saved-credential VM procedure](SavedCredential/README.md).

## Build and tests

From this directory:

    cd windows
    make build-release
    ctest --test-dir build -C Release --output-on-failure

The pure Components Wizard state tests are in
ComponentsWizardTests/main.cpp and cover empty state, complete installation,
partial installation, pending reboot cleanup, stale Installed state,
recovery-required state and unknown residue blocking. Real System32, LSA and
Task Scheduler behavior remains a disposable-VM test.

## Diagnostics and recovery

Diagnostics/Get-ComponentsStatus.ps1 is read-only. It reports architecture,
SHA-256 hashes, registrations, the HKLM transaction record and Task Scheduler
status.

Recovery/Invoke-ComponentsRecovery.ps1 only invokes the native
resume-uninstall entry point with elevation. The old component-specific
Install-Test and Uninstall-Test script paths are compatibility wrappers; they
no longer perform direct installation or rollback.

Windows-Unlock-Components-Wizard.ps1 remains a launcher for the native EXE.
LookupAuthenticationPackage.exe remains a read-only LSA lookup tool.
