<!-- Created by Rui MA on 27 Sep 2026 -->

# MSA credential probe (Gate A/B)

The V2 Credential Provider currently tests a password-based unlock of an
existing Microsoft Account console session in a disposable Windows VM. This is
the first gate of the planned iPhone-approved unlock path. It does not save the
password, call UnlockService, auto-submit, or construct a Windows token.

At LogonUI enumeration, it reads `GetSid()`, `PKEY_Identity_PrimarySid`,
`PKEY_Identity_QualifiedUserName`, `PKEY_Identity_UserName`, and
`GetProviderID()`. It writes these non-secret values, the active console
session ID, the account name reported for that session, and its resolved SID
to `unlock-msa-credential-probe.txt` in LogonUI's temporary directory
(normally `%SystemRoot%\Temp`). It rejects a mismatched primary SID, a
LogonUI process outside the active console session, or a selected SID that
differs from the session account SID. The previous `WTSQueryUserToken` call
was removed from the Credential Provider because it requires LocalSystem and
`SeTcbPrivilege`; this gate uses session metadata and `LookupAccountNameW`
instead. If either query fails, the tile fails closed and the report records
`consoleIdentityStage` and `consoleSidStatus`. Never include a password or a
serialized credential in a shared diagnostic report.

The password tile calls `CredPackAuthenticationBufferW` **inside LogonUI** with
`CRED_PACK_PROTECTED_CREDENTIALS | CRED_PACK_ID_PROVIDER_CREDENTIALS`, the
exact qualified user name supplied by Windows, and the manually entered MSA
password. It submits the result to the built-in `Negotiate` authentication
package. The password is wiped after the attempt or when the tile is deselected.
This tests a Windows authentication path; a successful pack alone is not proof
that MSA unlock works.

## VM result

Gate B succeeded in the disposable VM: the manually entered MSA password
unlocked the existing console session. The report recorded
`consoleIdentityStage=complete`, `consoleSidStatus=0`, and matching `userSid`,
`primarySid`, and `consoleSid`; `whoami /user` after unlock returned that same
SID. Native PIN sign-in remained available, while an incorrect password was
rejected. The desktop SID and session ID were unchanged, and `whoami /all`
showed no difference between the PIN- and MSA-password-unlocked desktop.
This is not a direct comparison of `TokenLinkedToken`; the separate read-only
desktop/linked-token baseline remains to be run once. No password was stored.

## VM procedure

1. Restore a disposable VM snapshot with the target MSA already signed in and
   a working system password or PIN recovery option. An old custom LSA package
   installation must be removed by restoring the snapshot; this wizard never
   changes LSA registration. If the previous Gate A/B Credential Provider is
   installed, restore its pre-install snapshot or use the wizard to uninstall
   it, restart, and finish cleanup before installing the new DLL. Do not
   overwrite a loaded DLL in System32.
2. On the development machine, build with `cd windows` followed by
   `make build-release`. Copy the resulting wizard EXE and
   `unlock_credential_provider.dll` to the VM. The VM needs no build tools.
3. Run `unlock_windows_components_wizard.exe` as administrator in the VM. It
   installs only the Credential Provider and records a version-2 HKLM
   transaction. Restart if requested.
4. Sign in with the original Windows method, lock the workstation, choose the
   **MSA password probe** tile, enter the actual MSA password, and select
   **Test unlock**. Do not test the first login after reboot as Gate B.
5. Read `%SystemRoot%\Temp\unlock-msa-credential-probe.txt` as administrator.
   Confirm `consoleIdentityStage=complete`, `consoleSidStatus=0`, and that
   `userSid`, `primarySid`, and `consoleSid` identify the same existing console
   user. If the session account cannot be resolved, preserve the new stage and
   status rather than bypassing the check. If an
   iPhone public key is already enrolled, compare the reported user SID with
   that enrollment's account SID; Gate B does not require enrollment. Retain
   the authentication result and run `whoami /user` in the unlocked session to
   confirm the same SID. Once Gate B succeeds, compare the desktop and linked
   token with the existing read-only token probe once.
6. Use the wizard's uninstall action and its post-restart cleanup before
   restoring the VM snapshot. Leave the system password/PIN provider enabled.

If the selected user is not the active console user, identity enumeration fails,
or Negotiate rejects the credential, stop at Gate B and preserve the status
without proceeding to password storage or automatic submission.

## References

- [Microsoft V2 Credential Provider sample](https://github.com/microsoft/Windows-classic-samples/blob/main/Samples/CredentialProvider/cpp/CSampleCredential.cpp)
- [ICredentialProviderUser::GetStringValue](https://learn.microsoft.com/en-us/windows/win32/api/credentialprovider/nf-credentialprovider-icredentialprovideruser-getstringvalue)
- [CredPackAuthenticationBuffer](https://learn.microsoft.com/en-us/windows/win32/api/wincred/nf-wincred-credpackauthenticationbuffera)
- [WTSQuerySessionInformationW](https://learn.microsoft.com/en-us/windows/win32/api/wtsapi32/nf-wtsapi32-wtsquerysessioninformationw)
- [ProcessIdToSessionId](https://learn.microsoft.com/en-us/windows/win32/api/processthreadsapi/nf-processthreadsapi-processidtosessionid)
- [LookupAccountNameW](https://learn.microsoft.com/en-us/windows/win32/api/winbase/nf-winbase-lookupaccountnamew)
