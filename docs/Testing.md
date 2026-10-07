<!-- Created by Rui MA on 03 Oct 2026 -->

# Testing and diagnostics

This guide describes reusable checks, not a personal test diary or a record that every scenario has passed. The author reports a relatively stable primary unlock workflow on their setup with one Windows user and a password-backed Microsoft Account (MSA). This report does not establish acceptance of the latest self-contained packaging changes. Broader compatibility, negative paths, oldest-Windows and ARM64 hardware remain to be established. See the [supported account scope](../README.md#requirements) and record results for the exact revision and matching binaries under test.

## Environment and evidence

Use a physical iPhone running iOS 26 or later, a BLE GATT-server-capable Windows PC and a password-backed MSA console account. Follow the [Windows](../windows/README.md) and [iOS](../ios/README.md) guides. Keep native Windows sign-in available. Use an isolated test environment for intrusive failure/caller/identity experiments; do not repeatedly submit incorrect real account passwords.

For each result record:

| Field | Evidence |
|---|---|
| Revision/build | Repository commit, Windows product version/configuration/native architecture and iOS app build/signing configuration. |
| Environment | Windows version/build, iOS version, phone model, Bluetooth adapter/driver and relevant settings. |
| Scenario | Preconditions, exact action, expected behavior and observed behavior. |
| Result | Pass, fail or not tested; source inspection, policy tests and physical-device observations are distinct evidence. |
| Diagnostics | Relevant UTC/monotonic timing, generation/request association and raw error codes in restricted evidence. |

Remove personal account names/SIDs, machine paths and device identifiers from public reports. Keep original identity fields privately when they are necessary to diagnose the boundary. Do not log or attach passwords, private keys, nonces or signature bodies.

## Automated checks

From the repository root on Windows:

```powershell
make -C windows test
```

This builds first and runs CTest. To run previously built Release tests without rebuilding:

```powershell
ctest --test-dir '.\windows\build' -C Release --output-on-failure
```

Adjust the test directory if using a separate architecture/configuration directory. Tests cover protocol/crypto, approval policy, enrollment storage, saved-credential IPC, CP policy and installer decisions. Test execution is different from verifying a native Windows installation or real BLE callbacks.

For the iOS policy tests, open `ios/ios.xcodeproj`, select the `ios` scheme and choose **Product → Test** (`⌘U`).

These cover initialization/readiness, RSSI/request state, per-route recovery/retry and generation/cancellation decisions. They do not emulate CoreBluetooth, the Secure Enclave or overnight OS scheduling.

Repository automation must continue to follow [AGENTS.md](../AGENTS.md), including its separate build/test authorization rule; the commands here are developer instructions, not recorded execution results.

## First-install setup

Use a clean installation with matching binaries; these are acceptance procedures, not recorded results.

1. Install, restart and complete exactly one native Windows sign-in. The phone tile must remain absent before that sign-in. Do not lock/unlock merely to obtain identity.
2. After verified installation completion, select **Start setup**. Confirm the displayed target account, save the actual account password and verify that the existing pairing window opens only after the service confirms storage.
3. Cancel UAC, close password management, reject saving and exercise a save error separately: none may launch pairing. Choose **Later** on the result page and resume with tray **Continue setup…**; the installation notification must not recur after acknowledgment.
4. Repeat Continue setup while a step is active: only one sequence may run. Existing credentials matching SID, QualifiedUserName and ProviderID skip saving; a mismatched saved identity requires updating the copy. Matching phone registration skips pairing only after a confirmed service reload; reload failure must remain retryable without advancing. Failed or cancelled pairing must remain resumable.
5. Wait beyond five minutes and Refresh the verified account without another sign-in. Inspect identity diagnostics on rejection. Verify service startup delay is handled by candidate transport retry; a service restart after LogonUI has gone must report missing identity rather than inventing it.
6. Switch accounts, log off, disconnect the physical console and use a different administrator for UAC. Stale candidates/nonces must not authorize a different user; elevation must not change the installed target. Resume only from the target's unlocked ordinary-user tray.
7. Finish pairing, lock Windows and exercise native password acceptance. A saved copy or phone approval is not proof of unlock. Check update/reinstall retain data and show their ordinary completion result; failures and uninstall must not start configuration.

## Minimum end-to-end check

1. Build both platforms from the same revision, install all four matching Windows components and complete any restart. Sign in with native Windows credentials.
2. Confirm ordinary-user tray startup, LocalSystem service and the single product entry. Choose Start setup after the first native sign-in and configure the saved password without an additional lock/sign-in cycle.
3. Pair the phone; check the target console account and full fingerprint. Confirm ComputerId and the completed enrollment result in the iOS app.
4. Lock Windows, press Enter / Unlock once, and confirm the actual desktop returns to the same account/session. Phone `unlock_approved` alone is insufficient.
5. Lock again without a new request/approval: remain locked. Start a fresh request and confirm another successful unlock. Check rapid repeated locking has no fixed approval cooldown and no old-grant reuse.
6. Restart Windows: initial sign-in must use the original password/PIN provider. After sign-in, verify tray startup and phone unlock of the next locked session.
7. Uninstall through Settings, honor the restart/result handoff, then inspect complete removal as described below. Delete the iPhone's computer record separately.

## Authentication and security boundaries

| Scenario | Expected behavior |
|---|---|
| Initial sign-in, signed-out account, other account or remote session | No eligible phone tile/credential claim; native sign-in remains available. |
| Wrong key/signature, malformed/truncated assertion, wrong requestID or replay | Reject; do not create or restore approval. |
| Preparation without full readiness, duplicate/wrong/expired receipt | Do not prematurely consume challenge, extend the deadline or approve twice. |
| No phone response, below-threshold or missing RSSI | Distinct failure/waiting reason; no credential release. |
| Account/SID/session/online identity change during a request | Reject mismatched saved identity and invalidate affected approval. |
| Service restart or actual unlock | Old outstanding request/grant cannot be claimed afterward. |
| CP re-enumeration/rebuild, notification loss, packing/native password failure | At most one eligible offer/claim; consumed approval is never restored. |
| Ineligible pipe caller, wrong endpoint/process/session | Reject; phone transport cannot claim credentials or issue a request. |

Confirm the service owns the original 30-second request deadline and never extends it for readiness or recovery. Preserve native login recovery for every failure test. Validate caller/identity probes in a controlled environment; do not load experimental authentication packages into a physical machine's LSA.

## Pairing and saved-password operations

- Check first registration, the same key/SID, explicit replacement and removal. Confirm replacement invalidates the previous phone and removal prevents its future approval.
- Check same-user UAC and another administrator's UAC: the target remains the original physical-console account.
- Check UAC/confirmation cancellation, timeout, lock/session change, sleep, disconnect, concurrent/second candidate, invalid public key and service/storage failure. Pre-commit failure preserves the old record; post-commit reload failure reports its actual saved state.
- Check manual enrollment requires elevation, full fingerprint and explicit `--replace`/removal confirmation. It does not initialize a tray or BLE authentication path.
- Check password save/update/remove, five-minute snapshot expiry/Refresh without a second sign-in and cancelled operations. Phone removal does not clear the password; password management does not change the online account password. Closing either operation leaves the tray alive.

## Connection and background recovery

Repeat at least twenty lock/request/unlock cycles, including a fifteen-minute and overnight phone-background interval, PC sleep/resume, phone leaving/returning, Bluetooth off/on and tray restart. During automatic-recovery trials do not Refresh GATT, reopen the phone app or press Retry. Record manual intervention as such, rather than counting it as automatic recovery.

Check these discriminating cases:

- After successful StopAdvertising, a stale raw Started property cannot suppress the next lock's start or cause repeated stop calls.
- Confirmed service absence releases the unusable route and waits for new advertising, without a reconnect/scan loop; usable connections are retained.
- An older restored pending route cannot block a newly advertised connected route. Cached route failures cannot reset retries merely because scanning restarts.
- Cancellation and late connect/discovery/write/RSSI callbacks cannot overwrite a newer ready generation or a different request.
- Suspended initialization past its ten-second deadline cannot become Ready on resume. Native pending-connection waiting does not inherit that deadline.
- The phone's three-second fresh RSSI/signing deadline remains distinct from result waiting and from the service's overall deadline.
- Stable ComputerId survives tray restart and routing UUID changes. A different ComputerId or merely matching name cannot be treated as the registered target.

Force-quit recovery is not promised. Collect both platforms' timelines to separate native connection waiting, initialization, subscription, readiness, challenge, signature and native password verification.

## Installer and removal

Self-contained packaging acceptance is pending. After explicit build authorization, build Release for the current target architecture and inspect normal and delay-load imports of setup and all three embedded components. There must be no Debug CRT, dynamic VC++ runtime or unprovided non-system dependencies. Copy only the setup EXE from `windows/dist/` to a clean machine of the same architecture without Visual Studio, CMake or VC++ Redistributable; verify installation, native sign-in after restart, service/tray startup and physical-device unlock. Older companion-file installations must first complete their transactions and be uninstalled with their original installer.

Check that rebuilding a changed component refreshes setup's embedded resource/manifest. Test missing/corrupt resources, mixed versions and wrong architecture before deployment; interrupt protected extraction and confirm preparation resumes with the same transaction and only marks `payloadReady` after every component is verified. Package resource hashes check integrity, not publisher identity. These checks do not authorize running builds or installers by themselves.

Test a clean install, same-version Reinstall, higher-version Update, downgrade rejection, restart continuation and explicit Uninstall. Confirm all four files match native architecture/version and the documented paths, and there is only one Settings entry. Cancellation before execution must preserve installation and records.

During update, hold an operation window open or start another installed-app instance: maintenance must wait/pause rather than forcibly kill it or claim files released. Check ordinary-user Run startup after native sign-in and preservation of a user's startup-disable choice.

For failure scenarios, check interrupted preparation, invalid package/version/architecture, replacement failure, deletion failure, unknown contents, unsafe ACL/reparse point, absent target user, result-handoff race and repeated continuation. The transaction must retain ownership and a real error/continuation path; incomplete finalization cannot be announced as success.

After completed install/update and Finish, verify staging and one-time result tasks/records are released. After repeated updates, only the current formal installation should remain.

After completed uninstall verify the service, CP/main/setup files, password and registration data, target user's ComputerId/Run entry, transaction staging/tasks/records and Settings entry are absent. Unknown files must block a full-removal success claim. No mounted offline hive or surviving product task should be overlooked. Removal does not erase iPhone data, backups or SSD history.

## UI and accessibility

On iOS, verify exactly five native slider ticks and the separate numeric row below them at −100, −80, −60, −40 and −20 dBm, with dBm shown on every label. Check that all five values remain visible in light/dark appearance and large text. Drag freely between ticks and select integers such as −73 and −57 dBm, then verify they remain selected after restarting the app. Values must not be restricted to the five ticks. The selected value and VoiceOver value must not show decimals. After approval, verify the icon and Request approved text remain synchronized for five seconds through ordinary disconnect/reconnect and waiting-state updates, then return to the current state. New authentication, failure and leaving the home page must interrupt the presentation; returning must not replay it.

Check that Last approval displays the approval time and that request’s signal strength in dBm separated by **/**, with no separate Signal strength row. Failure or no result must show **N/A**, and a pending request must preserve the previous completed result.

On iOS, push from the pairing introduction to verification, then return using both the system Back button and the interactive back gesture. Repeat the sequence without scrolling: the introduction’s close button must be visible immediately and dismiss the sheet. Cancelling an interactive back gesture must leave verification active with its system Back button.

On the cancellation page, verify there is no Back button, Done is the prominent primary action and Retry Pairing is a secondary action below it. Done must dismiss the sheet; Retry Pairing must start a new pairing attempt and show verification using the existing navigation stack.

Check Windows at 100/150/200/250% DPI and across monitors, including long account names/full fingerprints, keyboard/default focus and long logs. Check native slider ticks, numeric labels with dBm units and continuous adjustment, the pairing sheet/push/back flow and Cancel Pairing → cancellation page → Done dismissal, the Privacy Policy repository link and bundle-derived version/build in the transparent About footer. Check iOS light/dark appearance, large text, VoiceOver, Reduce Motion, long computer names, pairing success/failure/cancellation/retry and synchronized five-second icon/status presentation. Check removal clears only the phone target/history, retains its key/threshold and ignores late results. Check request-associated history survives restart, displays N/A after failure and is not replayed as a new approval. Error messages must distinguish current state from historical diagnostics and approval from completed unlock.

## Diagnostics

Start with Windows tray **Status… → Technical details** and iOS About → Diagnostics. Run the read-only inspector from the repository root:

```powershell
& '.\windows\Diagnostics\Get-ComponentsStatus.ps1'
```

Use `-BuildDirectory` for a nondefault build location. Access-denied/read errors are evidence, not proof a record is absent. The inspector does not run tasks, mount offline hives, clear data or repair installation.

If the tile waits, compare these stages in order: console/service eligibility → publication → matching ComputerId → both subscriptions → readiness probe/receipt → challenge delivery → fresh RSSI/signature → service verification → one-time CP submission → Windows native result. An absent connection is not an RSSI failure, and service approval is not the final native result.

For a published preview, include commit/build/environment and the actual exercised scenarios in its release notes. Do not carry personal historical test results forward as acceptance of another revision.
