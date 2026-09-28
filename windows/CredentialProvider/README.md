<!-- Created by Rui MA on 27 Sep 2026 -->

# Credential Provider prototype

This directory contains the build-only V2 Credential Provider shell supporting
CPUS_LOGON and CPUS_UNLOCK_WORKSTATION. It is installed only by the native
Components Wizard in a disposable Windows 10 or later VM.

The provider associates the current user SID through
ICredentialProviderSetUserArray and ICredentialProviderCredential2. Its
serialization adapter does not verify signatures or create a Windows token;
the LSA package must verify the shared logon buffer independently.

The normal VM flow is:

    cd windows
    make build-release

Copy the complete build directory to the disposable VM and run
unlock_windows_components_wizard.exe. The EXE requests elevation through its
embedded manifest, verifies native architecture, installs the Credential
Provider and LSA package together, and records one HKLM transaction.

Uninstall removes registrations before restart. The post-restart task removes
the DLLs and state only after verification. If the task needs an administrator
assisted retry, run Recovery/Invoke-ComponentsRecovery.ps1 or invoke the EXE
with the resume-uninstall argument.

The old PowerShell paths in this directory are compatibility wrappers only.
They do not copy files, edit the registry or maintain JSON backups. Use
Diagnostics/Get-ComponentsStatus.ps1 for read-only status.
