<!-- Created by Rui MA on 30 Sep 2026 -->

# Saved Windows credential (VM prototype)

This prototype stores a local copy of an MSA password for **manual unlock of an
existing physical-console session**. It is not an iPhone approval path and does
not auto-submit. The first VM run confirmed installation and identity display.
A later VM run used a freshly authorized saved credential, without typing a
password at the tile, to unlock the existing console SID and session. The VM
operator subsequently confirmed that a used authorization could not unlock a
second time, a new authorization could, and an authorization issued before a
service restart was refused afterward. Reauthorizing after that restart again
unlocked with the saved credential. Keep a usable native Windows PIN/password
tile and a disposable VM snapshot.

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

The Credential Provider first requests the identity nonce during user
enumeration so the manager can see the snapshot after a native unlock. If that
request runs before the service reports the console as locked, a manual saved
credential submission retries capture before claiming the password. The
`savedIdentityCapture` report field records only the enumeration-time result;
the submission retry remains subject to the service's locked-session and
identity checks. A retry failure does not consume or release the credential.
The pipe client handles immediately completed and pending overlapped I/O
separately. If the five-minute snapshot expires while a 120-second test grant
is still valid, a matching locked-console capture keeps that grant's nonce;
an identity or session change still revokes the grant.

The first VM run also showed intermittent manager Refresh transport failures.
The service previously disconnected its only pipe instance immediately after
writing a reply, which could discard unread reply bytes. It now waits at most
two seconds for an acknowledgment sent only after the client has read the full
reply, then disconnects. A missing acknowledgment is diagnostic, not a reason
to replay an operation or restore a consumed test grant. The manager displays
the failing IPC stage and Win32 code on Refresh; `reply-read` points at reply
delivery, whereas `wait-for-pipe` or `open-pipe` points at connection pressure.
The client also retries a `CreateFileW`/`ERROR_PIPE_BUSY` race within its
existing timeout. The updated binaries were deployed in the VM and repeated
manager Refresh was stable. A later controlled sequence established behavioral
one-shot rejection: a successful saved-credential unlock was followed by a
refused attempt without new authorization, then another successful unlock
after new authorization. Earlier claim-refused and active-console messages
alone did not establish that result.

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
   `unlock_saved_credential_manager.exe` from the **same build** into one VM
   folder. The VM does not need a compiler. The wizard installs the service and
   Credential Provider; the manager stays in the VM folder. Do not install
   alongside an old custom LSA package or overwrite a loaded Credential
   Provider DLL.
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
   usable. The current VM has confirmed the service-restart behavior, a used
   authorization's rejection, fresh reauthorization, and native PIN/password
   recovery after refusal. Identity changes and wrong session/caller still need
   direct evidence. The separate desktop/linked-token baseline remains another
   task. A full Windows reboot reaches first logon rather than the supported
   existing-session unlock scenario, so its refused claim is not a substitute
   for these tests.
6. Normal wizard removal first asks the service to confirm credential deletion,
   seals further credential operations in that service process, then removes
   registrations and, after restart, component files. If deletion
   cannot be confirmed it stops instead of claiming complete removal. The
   explicit `unlock_windows_components_wizard.exe --emergency-remove` path is
   for a damaged disposable VM: it warns, removes known components, and
   preserves an `RemovedUnconfirmed` diagnostic state when the secret could
   not be confirmed absent. File deletion does not erase VM snapshots,
   backups, or physical SSD history.

## VM acceptance record (1 Oct 2026)

- Passed (operator-reported): saved-credential unlock with unchanged console
  SID/session; after a successful claim, another attempt without authorization
  was refused, while a new authorization worked. Authorization issued before
  `Restart-Service UnlockWindowsSavedCredentialService` was refused after the
  restart; reauthorization then worked with the stored credential. This is
  behavioral evidence that the secret survives service restart and the old
  grant cannot unlock after restart. The generic refusal message alone does
  not identify which service check rejected the request.
- Passed (operator-reported): native PIN/password recovered the session after
  refusal. Normal wizard uninstall reported confirmed credential deletion;
  querying the former vault path afterward returned not found. Before removal,
  an administrator's `Get-Item`/`icacls` access to the vault file was denied,
  while `icacls` on its directory showed `NT AUTHORITY\SYSTEM:(F)` only.
- Not directly verified: the vault file's ciphertext from a SYSTEM context;
  the administrator access denial is expected from the ACL, not proof of the
  DPAPI bytes on disk. The implementation uses LocalSystem user-scope DPAPI.
  Also unverified: changed QualifiedUserName/ProviderID under the same SID,
  wrong session/non-LogonUI caller rejection, emergency removal, and behavior
  under an unavailable service. Do not change the only VM's account linkage
  merely to force an identity mismatch.

## References

- [CryptProtectData](https://learn.microsoft.com/en-us/windows/win32/api/dpapi/nf-dpapi-cryptprotectdata)
- [ICredentialProviderSetUserArray::SetUserArray](https://learn.microsoft.com/en-us/windows/win32/api/credentialprovider/nf-credentialprovider-icredentialprovidersetuserarray-setuserarray)
- [ICredentialProviderUser::GetProviderID](https://learn.microsoft.com/en-us/windows/win32/api/credentialprovider/nf-credentialprovider-icredentialprovideruser-getproviderid)
- [WTSQuerySessionInformationW](https://learn.microsoft.com/en-us/windows/win32/api/wtsapi32/nf-wtsapi32-wtsquerysessioninformationw)
- [WTSINFOEX_LEVEL1_W lock state](https://learn.microsoft.com/en-us/windows/win32/api/wtsapi32/ns-wtsapi32-wtsinfoex_level1_w)
- [Named pipe security](https://learn.microsoft.com/en-us/windows/win32/ipc/named-pipe-security-and-access-rights)
- [DisconnectNamedPipe unread-data behavior](https://learn.microsoft.com/en-us/windows/win32/api/namedpipeapi/nf-namedpipeapi-disconnectnamedpipe)
- [PeekNamedPipe](https://learn.microsoft.com/en-us/windows/win32/api/namedpipeapi/nf-namedpipeapi-peeknamedpipe)
- [Named pipe client connection handling](https://learn.microsoft.com/en-us/windows/win32/ipc/named-pipe-client)
- [ImpersonateNamedPipeClient](https://learn.microsoft.com/en-us/windows/win32/api/namedpipeapi/nf-namedpipeapi-impersonatenamedpipeclient)
