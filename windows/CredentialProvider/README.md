<!-- Created by Rui MA on 27 Sep 2026 -->

# Credential Provider

The **Unlock with iPhone®** tile is offered only for an existing, explicitly locked physical-console session. Initial sign-in, signed-out users, other accounts and remote sessions are ineligible. Windows can use `CPUS_LOGON` for unlocking; the scenario enum alone does not establish eligibility. Native Windows password/PIN providers remain available.

## Enumeration and requests

CP captures SID, PrimarySid, original QualifiedUserName and ProviderID from the system user objects. Before requiring an existing console user, it submits the installer-recorded target as a provisioning candidate over a separate operation. Transport failures retry on a cancellable worker for the current LogonUI lifetime; rejection is reported rather than bypassed. This path cannot create an unlock tile, snapshot nonce or approval.

For phone unlocking, CP checks console identity and asks the service for `unlockEligibility`, without inventing account names or falling back to a lone candidate.

The tile contains the provider icon, title and **Unlock** action; it does not accept typed passwords or test approvals. Enter / Unlock starts `beginVerification`. Selection and locking alone do not create requests. Initial enumeration has `autoLogon=FALSE`; default tile selection remains controlled by LogonUI.

Manual initiation waits without blocking on BLE. Verification and automatic submission show **Just a moment...** instead of **Unlock**. Provider failures replace the title with the reason and **OK**, which resets the tile without retrying; native errors use Windows' error screen. A worker queries status by requestID and marshals UI changes onto the COM/Advise thread. The service's 15-second deadline covers verification, not native authentication. Deselection cancels the request; late operations cannot create a grant.

## Automatic submission

The waiting worker polls `takeAutoSubmitOffer` before verification status. Its message window calls `CredentialsChanged` on the Advise thread; the next eligible enumeration exposes automatic submission once. `GetSerialization` validates the current captured identity/nonce and offer before claiming the password.

The service rechecks 3-second communication/RSSI evidence and consumes authorization before decrypting the password. CP packs credentials in LogonUI using protected/ID-provider flags and submits to native Negotiate. It does not construct a token or call `LsaLogonUser`. Only native authentication confirms actual unlock.

After successful serialization, `ReportResult` reports its claim nonce and native status to the service once. A matching native success updates **Last Unlock**; rejection, packing failure and missing reports do not. Reporting uses the existing bounded pipe call, logs failures and leaves Windows authentication unchanged.

Matching identity/session re-enumeration can retain an unsubmitted offer. Identity changes and UnAdvise retire worker state. Idle status ends waiting with an error and **OK**; pre-attempt samples are ignored. Missing notifications, serialization failure or native password rejection cannot restore a consumed approval or reissue its offer; another attempt requires a fresh presence request.

## Presentation and deployment

Status text distinguishes presence verification, signal failure, disconnection, timeout, verification failure, service failure and genuine session changes. Approval is shown as an unlock attempt, not completed success.

`AppTile.bmp` is the existing product icon and is a provider logo, not a replacement user avatar. LogonUI controls tile typography; desktop DPI settings are not injected into CP.

Install/update through the [installer](../Setup/README.md) and honor its restart boundary. Do not overwrite a DLL already loaded by LogonUI. Service, CP and app must be from the same build. Verify repeated enumeration, single consumption and native-login recovery.

## References

- [Microsoft V2 Credential Provider sample](https://github.com/microsoft/Windows-classic-samples/blob/main/Samples/CredentialProvider/cpp/CSampleCredential.cpp)
- [CredentialsChanged](https://learn.microsoft.com/en-us/windows/win32/api/credentialprovider/nf-credentialprovider-icredentialproviderevents-credentialschanged)
- [GetCredentialCount and automatic submission](https://learn.microsoft.com/en-us/windows/win32/api/credentialprovider/nf-credentialprovider-icredentialprovider-getcredentialcount)
