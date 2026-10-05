<!-- Created by Rui MA on 27 Sep 2026 -->

# Credential Provider

The **Unlock with iPhone®** tile is offered only for an existing, explicitly locked physical-console session. Initial sign-in, signed-out users, other accounts and remote sessions are ineligible. Windows can use `CPUS_LOGON` for unlocking; the scenario enum alone does not establish eligibility. Native Windows password/PIN providers remain available.

## Enumeration and requests

CP captures SID, PrimarySid, original QualifiedUserName and ProviderID from the system user objects. Before requiring an existing console user, it submits the installer-recorded target as a provisioning candidate over a separate operation. Transport failures retry on a cancellable worker for the current LogonUI lifetime; rejection is reported rather than bypassed. This path cannot create an unlock tile, snapshot nonce or approval.

For phone unlocking, CP checks console identity and asks the service for `unlockEligibility`, without inventing account names or falling back to a lone candidate.

The tile contains the app logo, title and **Unlock** action; it does not accept typed passwords or test approvals. Enter / Unlock starts `beginPhoneAuthentication`. Selection and locking alone do not create requests. Initial enumeration has `autoLogon=FALSE`; default tile selection remains controlled by LogonUI.

Manual initiation returns a no-credential waiting state rather than blocking on BLE. A worker queries structured service status by requestID and marshals UI changes onto the COM/Advise thread. The service owns the deadline.

## Automatic submission

When approval becomes available, the worker obtains one `takeAutoSubmitOffer`. The message window calls `CredentialsChanged` on the Advise thread; the next eligible enumeration exposes automatic submission once. `GetSerialization` validates the current captured identity/nonce and offer before claiming the password.

The service consumes approval before releasing plaintext. CP packs credentials in LogonUI using protected/ID-provider flags and submits to native Negotiate. It does not construct a token or call `LsaLogonUser`. Only native authentication confirms actual unlock.

Matching identity/session re-enumeration can retain an unsubmitted offer. Identity changes and UnAdvise retire worker state. Missing notifications, serialization failure or native password rejection cannot restore a consumed approval or reissue its offer; another attempt requires a fresh phone request.

## Presentation and deployment

Status text distinguishes phone waiting, signal failure, disconnected transport, automatic response off, timeout, verification failure, service failure and genuine session changes. Approval is shown as an unlock attempt, not completed success.

`AppTile.bmp` is derived from the standard iOS icon and is a provider logo, not a replacement user avatar. LogonUI controls tile typography; desktop DPI settings are not injected into CP.

Install/update through the [installer](../ComponentsWizard/README.md) and honor its restart boundary. Do not overwrite a DLL already loaded by LogonUI. Service, CP and app must be from the same build. Use the [testing guide](../../docs/Testing.md#authentication-and-security-boundaries) for repeated enumeration, single consumption and native-login recovery.

## References

- [Microsoft V2 Credential Provider sample](https://github.com/microsoft/Windows-classic-samples/blob/main/Samples/CredentialProvider/cpp/CSampleCredential.cpp)
- [CredentialsChanged](https://learn.microsoft.com/en-us/windows/win32/api/credentialprovider/nf-credentialprovider-icredentialproviderevents-credentialschanged)
- [GetCredentialCount and automatic submission](https://learn.microsoft.com/en-us/windows/win32/api/credentialprovider/nf-credentialprovider-icredentialprovider-getcredentialcount)
