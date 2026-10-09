<!-- Created by Rui MA on 03 Oct 2026 -->

# Testing and diagnostics

This guide defines acceptance checks, not recorded results. Packaging, broader compatibility, failure scenarios, oldest-Windows and ARM64 hardware validation remain pending. Follow the [system requirements](../README.md#system-requirements) and record results for the exact revision under test.

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

Adjust the test directory as needed. Windows tests cover protocol/crypto, approval policy, enrollment storage, saved-credential IPC, CP policy and installer decisions.

For the iOS policy tests, open `ios/ios.xcodeproj`, select the `ios` scheme and choose **Product → Test** (`⌘U`).

These cover readiness, RSSI/request state, recovery and cancellation. Policy tests do not replace native installation, BLE, Secure Enclave or background device testing.

Build/test authorization follows [AGENTS.md](../AGENTS.md).

The [Release workflow](../.github/workflows/release.yml) builds and checks packages only; it does not run tests, sign the IPA or verify device operation.

## First-install setup

Alongside the end-to-end check below, verify these setup cases:

- Pairing opens only after the service confirms password storage. UAC cancellation, closing password management, rejected saving and save errors must not launch pairing.
- **Later** allows resuming through tray **Continue setup…**, without repeating the acknowledged installation notification. Repeated Continue setup starts only one sequence; failed/cancelled pairing remains resumable.
- Matching SID, QualifiedUserName and ProviderID skip password saving. Mismatched identity requires updating the copy. Existing pairing is skipped only after confirmed service reload; reload failure must allow retry without advancing.
- After five minutes, Refresh renews the verified identity without another sign-in. Startup delay permits transport retry; a service restart after LogonUI exits reports missing identity rather than inventing it.
- Account changes, sign-out, console disconnection and another administrator's UAC must not let stale candidates/nonces authorize another user or change the installation target. Resume only from the target's unlocked tray.
- Update/reinstall retain data and show their normal completion result. Failures and uninstall must not start configuration.

## Minimum end-to-end check

1. Build both platforms from the same revision, install all four matching Windows components and complete any restart. Sign in with native Windows credentials.
2. Confirm ordinary-user tray startup, LocalSystem service and the single product entry. Choose **Start setup**, confirm the target account and save its password without an additional lock/sign-in cycle.
3. Pair the phone; check the target console account and full fingerprint. Confirm ComputerId and the completed enrollment result in the iOS app.
4. Lock Windows, press Enter / Unlock once, and confirm the actual desktop returns to the same account/session. Phone `unlock_approved` alone is insufficient.
5. Lock again without a new request/approval: remain locked. Start a fresh request and confirm another successful unlock. Check rapid repeated locking has no fixed approval cooldown and no old-grant reuse.
6. Restart Windows: the phone tile must be absent before the first native password/PIN sign-in. After sign-in, verify tray startup and phone unlock of the next locked session.
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

Inspect normal and delay-load imports of Release setup and all three embedded components: no Debug CRT, dynamic VC++ runtime or unprovided non-system dependencies. Copy only the setup EXE to a clean machine of the same architecture without development tools or VC++ Redistributable, then run the end-to-end check. See the [installer guide](../windows/ComponentsWizard/README.md) for installation compatibility.

Check that component changes refresh setup's embedded resources/manifest. Reject missing/corrupt resources, mixed versions and wrong architecture before deployment. Interrupted extraction must resume the same transaction and set `payloadReady` only after every component is verified. Resource hashes verify integrity, not publisher identity.

Test a clean install, same-version Reinstall, higher-version Update, downgrade rejection, restart continuation and explicit Uninstall. Confirm all four files match native architecture/version and the documented paths, and there is only one Settings entry. Check the all-users Start Menu shortcut opens/activates the main window without elevation after install/update and is removed on uninstall. Cancellation before execution must preserve installation and records.

Version 0.1.0 installations and pending transactions must be rejected without modification. Use their original installer to complete and uninstall them. For the current schema, interrupt replacement before and after the resident installer is replaced; continuation must verify staging and finish without rollback backups or obsolete runtime files.

During update, hold an operation window open or start another installed-app instance: maintenance must wait/pause rather than forcibly kill it or claim files released. Check ordinary-user Run startup after native sign-in and preservation of a user's startup-disable choice.

For failure scenarios, check interrupted preparation, invalid package/version/architecture, replacement failure, deletion failure, unknown contents, unsafe ACL/reparse point, absent target user, result-handoff race and repeated continuation. The transaction must retain ownership and a real error/continuation path; incomplete finalization cannot be announced as success.

After completed install/update and Finish, verify staging and one-time result tasks/records are released. After repeated updates, only the current formal installation should remain.

After completed uninstall verify the service, CP/main/setup files, password and registration data, target user's ComputerId/Run entry, transaction staging/tasks/records and Settings entry are absent. Unknown files must block a full-removal success claim. No mounted offline hive or surviving product task should be overlooked. Removal does not erase iPhone data, backups or SSD history.

## Diagnostics

Start with Windows tray **Status… → Diagnostics** and iOS Settings → Diagnostics. Run the read-only inspector from the repository root:

```powershell
& '.\windows\Diagnostics\Get-ComponentsStatus.ps1'
```

Use `-BuildDirectory` for a nondefault build location. Access-denied/read errors are evidence, not proof a record is absent. The inspector does not run tasks, mount offline hives, clear data or repair installation.

If the tile waits, compare these stages in order: console/service eligibility → publication → matching ComputerId → both subscriptions → readiness probe/receipt → challenge delivery → fresh RSSI/signature → service verification → one-time CP submission → Windows native result. An absent connection is not an RSSI failure, and service approval is not the final native result.

For a published preview, include commit/build/environment and the actual exercised scenarios in its release notes. Do not carry personal historical test results forward as acceptance of another revision.
