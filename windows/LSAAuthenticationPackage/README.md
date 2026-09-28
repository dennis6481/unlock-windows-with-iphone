# LSA Authentication Package

This directory contains the build-only LSA package prototype and the
read-only LookupAuthenticationPackage tool. The package is installed only by
the native Components Wizard in a disposable Windows 10 or later VM.

The wizard saves the original Authentication Packages REG_MULTI_SZ in the
single HKLM transaction record, verifies native x64 or ARM64 architecture,
creates normal System32 DLLs and registers only the package base name.
Uninstall restores the registry configuration before restart and deletes the
DLL only during post-restart cleanup.

The LSA package lookup tool makes no changes:

    windows\build\unlock_lsa_package_lookup.exe

A successful package ID lookup after reboot only proves that LSASS loaded the
development package. LSA Protection, signing and production compatibility
remain separate requirements.

The old Install-Test and Uninstall-Test PowerShell paths are compatibility
wrappers only. They no longer edit the registry, copy System32 files or
maintain JSON backups. Use Diagnostics/Get-ComponentsStatus.ps1 for inspection
and Recovery/Invoke-ComponentsRecovery.ps1 for an administrator-assisted
retry of the native post-restart cleanup entry point.
