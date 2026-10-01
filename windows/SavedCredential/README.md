<!-- Created by Rui MA on 30 Sep 2026 -->

# Saved Windows credential (VM prototype)

This prototype stores a local copy of an MSA password for **manual unlock of an
existing physical-console session**. It is not an iPhone approval path and does
not auto-submit. The code has received static review only; it has **not** been
built, installed, or validated in a VM as part of this change. Keep a usable
native Windows PIN/password tile and a disposable VM snapshot.

The identity source is the existing Credential Provider's current LogonUI user
enumeration: SID, PrimarySid, Windows-supplied QualifiedUserName and ProviderID.
The service accepts a five-minute, non-secret snapshot only from the locked
console's LogonUI process. After native PIN/password unlock, the separate
administrator manager displays the snapshot for confirmation. The target is
the **console user**, not the elevated manager's token user; this matters for
over-the-shoulder UAC. The encrypted record binds the SID, exact qualified
name, and ProviderID. LogonUI receives the fresh snapshot nonce and returns it
with the manual claim. A changed online identity requires re-enrollment even
if its local SID remains the same.

The `UnlockWindowsSavedCredentialService` runs as LocalSystem. Its vault is
`%ProgramData%\UnlockWindowsSavedCredential\saved-credential.dat`; both the
directory and file have a protected SYSTEM-only DACL. It uses LocalSystem
**user-scope** DPAPI with `CRYPTPROTECT_UI_FORBIDDEN`, without
`CRYPTPROTECT_LOCAL_MACHINE`. The DACL is access control, not a defense
against an administrator who has obtained SYSTEM. The manager's password
prompt asks Windows not to persist a second credential copy. Passwords are
not put in the identity report. The disk record keeps only a format header
and a DPAPI ciphertext; the SID, QualifiedUserName, ProviderID, and password
are all inside the protected payload.

The service's dedicated local-only pipe uses a restricted DACL, rejects remote
connections, and authorizes each operation. For a claim it pins the client
process handle, compares the process and actual pipe-client tokens, verifies
the SYSTEM LogonUI image/session, and checks the currently locked physical
console and the exact stored identity. The 120-second test authorization lives
only in service memory and is consumed **before** DPAPI decryption. Failure
to pack, authenticate, or keep the tile alive does not restore it. Credential
packing remains in the Credential Provider's LogonUI session; the service
never creates a Negotiate buffer. This boundary does not defend against an
attacker who already controls SYSTEM.

## VM procedure (after separate build and install authorization)

1. Build on the development machine. Copy the prebuilt
   `unlock_windows_components_wizard.exe`, `unlock_credential_provider.dll`,
   `unlock_saved_credential_service.exe`, and
   `unlock_saved_credential_manager.exe` into one VM folder. The VM does not
   need a compiler. The wizard installs the service and Credential Provider;
   the manager stays in the VM folder. Do not install alongside an old custom
   LSA package or overwrite a loaded Credential Provider DLL.
2. Run the wizard elevated, restart as requested, and sign in with native
   PIN/password. Lock the **existing** session, wait for the MSA tile to
   enumerate, then unlock with the native PIN/password. Launch the manager
   elevated on this physical console and select **Refresh**. Confirm the SID,
   Windows QualifiedUserName and ProviderID are the intended identity.
3. Select **Set credential** (or **Update stored**). Enter the actual MSA
   password. This sets a *local copy*; it does not change the online MSA
   password and does not yet prove that the copy can unlock Windows.
4. Select **Authorize one test**, lock within 120 seconds, choose the MSA
   tile's **Use saved credential (VM test)** checkbox, and click **Test
   unlock**. Do not type a password in the tile for this test. Confirm the
   existing SID and console session are restored. A failed claim requires a
   new explicit authorization. Try an incorrect stored password at most once
   in a controlled VM snapshot to avoid Windows retry delays.
5. Verify separately: identity changes reject release; service restart keeps
   the encrypted record but loses the test authorization; a second claim or
   wrong session/caller is rejected; and the native PIN/password tiles remain
   usable. Do not mark the saved-credential path validated until all four
   properties have VM evidence. The separate desktop/linked-token baseline
   remains a different task.
6. Normal wizard removal first asks the service to confirm credential deletion,
   seals further credential operations in that service process, then removes
   registrations and, after restart, component files. If deletion
   cannot be confirmed it stops instead of claiming complete removal. The
   explicit `unlock_windows_components_wizard.exe --emergency-remove` path is
   for a damaged disposable VM: it warns, removes known components, and
   preserves an `RemovedUnconfirmed` diagnostic state when the secret could
   not be confirmed absent. File deletion does not erase VM snapshots,
   backups, or physical SSD history.

## References

- [CryptProtectData](https://learn.microsoft.com/en-us/windows/win32/api/dpapi/nf-dpapi-cryptprotectdata)
- [ICredentialProviderSetUserArray::SetUserArray](https://learn.microsoft.com/en-us/windows/win32/api/credentialprovider/nf-credentialprovider-icredentialprovidersetuserarray-setuserarray)
- [ICredentialProviderUser::GetProviderID](https://learn.microsoft.com/en-us/windows/win32/api/credentialprovider/nf-credentialprovider-icredentialprovideruser-getproviderid)
- [WTSQuerySessionInformationW](https://learn.microsoft.com/en-us/windows/win32/api/wtsapi32/nf-wtsapi32-wtsquerysessioninformationw)
- [WTSINFOEX_LEVEL1_W lock state](https://learn.microsoft.com/en-us/windows/win32/api/wtsapi32/ns-wtsapi32-wtsinfoex_level1_w)
- [Named pipe security](https://learn.microsoft.com/en-us/windows/win32/ipc/named-pipe-security-and-access-rights)
- [ImpersonateNamedPipeClient](https://learn.microsoft.com/en-us/windows/win32/api/namedpipeapi/nf-namedpipeapi-impersonatenamedpipeclient)
