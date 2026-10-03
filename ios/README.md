<!-- Created by Rui MA on 03 Oct 2026 -->

# iOS Bluetooth unlock

## Current status

2026-10-03: after the service-invalidation/UI revision, the user observed another lifecycle failure: registration succeeded, but service discovery failed on the unlocked desktop; later locking Windows did not recover the phone until explicit retry or foreground re-entry. The user confirmed this first failure occurred on the unlocked desktop. The code exhausted its retry budget and stopped scanning. This revision separates passive waiting from bounded initialization. Only static inspection has been performed; no build, test execution, installation, or device acceptance of this revision has been performed.

Windows remains the authentication authority. The flow is an existing locked console session → Enter on the phone tile → a fresh RSSI/signature response → Windows approval → CP automatic submission. The iPhone does not store the Windows password. `unlock_approved` means approval, not confirmed desktop unlock.

## Connection and recovery

- `BluetoothAuthenticationState` is the production initialization/RSSI policy also exercised by the pure Swift tests. `BluetoothAuthenticator` owns CoreBluetooth operations and publishes one structured snapshot; the model does not overwrite connection status with enrollment/authentication strings.
- Only a verified computer identity and both challenge/result subscriptions establish Ready. Merely connecting does not reset the retry budget or authorize signing.
- Service invalidation discards old characteristics and the pending authentication, then rediscovers on the same connection. Discovery operations are serialized; repeated invalidations request a coalesced follow-up pass without extending the existing deadline.
- Waiting for a remembered target connection has no ten-second deadline. The system owns a single pending connection and service-filtered scanning; cached peripheral UUID only routes this request, never authorizes signing. Unknown candidate connection probes and actual service initialization retain fixed ten-second windows. Each initialization cycle permits one active reconnect; exhaustion leaves passive waiting and an explicit phase error, not a global scan block.
- Empty service discovery means only that this pass did not find the unlock service. Keep the physical connection, invalidate its authentication eligibility, and wait for service-change events; show “Bluetooth connected, waiting for unlock service.” This does not assert Windows lock state or that components are missing.
- A real service-change event can recover both service-wait and failed initialization states. A newly delivered service-advertisement event for the same connected peripheral also starts one bounded discovery pass, deduplicated within the scan round; recovery does not assume duplicate advertisement callbacks will arrive. An outstanding discovery callback must drain before the follow-up pass; repeated changes cannot extend the active deadline. Late RSSI, discovery, notification and write callbacks cannot establish Ready without a new ComputerId check and both subscriptions.
- After disconnection from Ready/service-wait, keep a remembered-target pending connection alongside scanning. New peripheral UUID candidates can replace a passive pending connection through serialized cancellation and identity verification. Scanning starts a bounded recent-candidate history per scan round, not a lifetime UUID blacklist; a full history evicts its oldest entry rather than excluding every future candidate. Active recovery/handoff does not restart scanning solely to reset deduplication and retry budgets.
- Foreground re-entry reconciles missing system operations; it does not reset normal waiting or automatically grant more retries to a failed initialization. Explicit retry remains available. There is no polling timer or infinite connect/discover loop. Automatic off and Bluetooth unavailability stop operations without changing the saved preference.
- A service change does not clear an outstanding RSSI read. Its callback is drained and rejected when generation/request differ. A missing callback has its own three-second deadline and may trigger bounded connection recovery.
- Authentication uses a new RSSI read per challenge, with a three-second RSSI/signing deadline and an adjustable default −60 dBm threshold. Recent displayed readings are never reused. Result waiting after sending a signature is not an RSSI timeout.
- Writes retain their characteristic, connection generation and request/enrollment association until acknowledgment. Old callbacks cannot overwrite a later operation. Queues and diagnostics are bounded.

## Stable target and migration

Windows already provides the following contract (introduced in `cd11511`):

| Item | Value |
|---|---|
| Service | `F1E2D3C4-B5A6-4789-8012-3456789ABCDE` |
| ComputerId read characteristic | `F1E2D3C4-B5A6-4789-8012-3456789ABCD5` |
| Value | Exactly 36 UTF-8 UUID characters; nonzero UUID |
| Windows persistence | Target user's `HKCU\\Software\\UnlockWindowsWithIPhone\\GattHost\\ComputerId` |

The iPhone scans by service, connects to candidates, and reads ComputerId before signing. One registered ComputerId is stored; peripheral UUID is only a routing cache/preference and the name is only display text. A changed peripheral UUID does not require registration again. A same-name but different ComputerId is not accepted. ComputerId is not a cryptographic server identity and does not replace Windows signature verification.

This update explicitly requires one new Windows-confirmed registration for old UUID-only iPhone records. It preserves the existing Secure Enclave key. Only `enrollment_saved` or `enrollment_already_registered`, with a valid ComputerId and no service reload failure, offers a replacement target. Cancellation, rejection, errors and `saved_reload_failed` preserve the previous valid target. If Windows has lost its persistent ComputerId, explicit registration is required; no name-based fallback is used.

The new iPhone record is `registeredWindowsComputer` in UserDefaults: ComputerId, display name and last peripheral UUID. The old `unlockTargetPeripheral` key is removed only after a valid record is saved.

## UI and automatic-response preference

- The Home Screen app name is managed by the target's Display Name setting (`INFOPLIST_KEY_CFBundleDisplayName`). `App/Info.plist` references that build setting instead of duplicating the name; keep Debug and Release values aligned. The in-app navigation title is separate.
- Home uses a large computer symbol and the registered computer name, with a separate connection/authentication status card. Actionable errors and failed-connection Retry remain visible; Bluetooth implementation details, RSSI controls and usage notes are in Settings.
- Home connection and authentication status lines debounce ordinary presentation changes for 300 ms, with text, icon and color updated together. Equivalent preparation phases share the same presentation and do not restart the delay. Initial status, approval, rejection, pause, Bluetooth unavailability and connection errors display immediately; error details and Retry remain live. Diagnostic states and the approval animation are not debounced. “Waiting for unlock service” does not imply that Windows is unlocked.
- Home maps both waiting-for-computer and waiting-for-service phases to “正在搜索Windows电脑”; their original phases remain visible in diagnostics. With automatic response off and no active enrollment, these waiting phases instead show “自动响应已暂停” immediately. This does not assert that Windows is unlocked.
- iOS recognizes the existing Windows rejection codes `rssi_too_low`, `automatic_disabled`, `rssi_unavailable`, `signing_failed` and `transport_failed`, retaining their raw codes in diagnostics instead of classifying them as `unknown_result`. Their user messages are respectively “请靠近电脑后重试”, “本次无法自动解锁，请检查设置”, “暂时无法判断距离，请重试”, “本次认证未完成，请重试” and “与电脑的连接出现问题，请重试”. Local low-signal rejection uses the same message as its Windows acknowledgment; diagnostics still retain RSSI and threshold. The existing reason behind `automatic_disabled` also covers other eligibility failures, so its message does not assert that the user turned off automatic response. This revision changes only text and result-code display recognition, not approval decisions or transport behavior. Validation is static only; device acceptance remains pending.
- The gear opens a Settings sheet with its own navigation stack. Automatic response and the unchanged RSSI threshold/range, recent reading and timestamp are here. Register/Re-register is in Settings; an unregistered phone also has a Home registration button.
- Registration information and the latest 64 diagnostics are a pushed detail page in Settings, not an expandable disclosure. Full connection/authentication states, ComputerId, fingerprint and errors remain available.
- While Home is visible in the foreground, a new approved request changes `desktopcomputer` directly to `lock.open.desktopcomputer` using the native Magic Replace symbol transition at normal speed. Processing keeps the ordinary computer symbol; no closed-lock computer symbol is shown. The open symbol returns to `desktopcomputer` five seconds after approval. Ordinary connection/authentication updates do not interrupt this approval feedback. A new approved request restarts the five-second timer; sheet presentation or foreground departure cancels the pending reset and restores the ordinary computer symbol. Opening Home or returning from the background does not replay an earlier approval. Reduce Motion disables the animated transition.
- This is approval feedback, not live Windows lock state: `unlock_approved` precedes credential submission, and the existing backend does not notify iOS of actual desktop unlock. No model, Bluetooth, authentication, registration, lifecycle or Windows logic changed for this UI revision.
- UI revision validation: static inspection only; no build, compilation, test execution, packaging, installation or device visual acceptance performed. Dark/light appearance, large text, long names, VoiceOver, Reduce Motion, sheet navigation and native symbol motion remain to be visually accepted.
- Removed constant Connect/Stop buttons and manual key preparation, local signature testing and raw public-key clipboard actions.
- Registration uses its own sheet: Start registration, Cancel registration while active, Finish afterwards. The Windows fingerprint must still be confirmed locally.
- Retry connection appears on failure; it does not re-enroll or create Windows approval.
- Automatic response defaults to on. Preference version 2 silently turns it on once on upgrade; subsequent explicit user changes are preserved. Disconnect, missing target, Bluetooth failure and enrollment failure do not change or disable the toggle.
- Recent diagnostics retain at most 64 entries: controlled phases, timings, subscription flags, RSSI, bounded recovery and allowlisted result codes. No passwords, keys, candidate public-key data, nonces or signature bodies are logged.

## UI visual acceptance (pending)

- Check Home and Settings in light/dark appearance, accessibility text sizes and with a long computer name; text must wrap and Home must remain scrollable.
- Check VoiceOver labels for Settings, registration, Retry and the RSSI slider; the decorative computer symbol is hidden from accessibility.
- Confirm the initial registration button appears only without a target. Settings → Re-register must retain the existing Start/Cancel/Finish flow and dismissal restriction while registration is active.
- Open Settings → Registration information and diagnostics; confirm metadata, full states, errors and logs appear directly without an expansion action.
- With Home visible in the foreground, check ordinary computer during processing → open-lock computer on approval → ordinary computer five seconds after approval, with symbol transitions at normal speed. During the five-second display, check connection changes and authentication returning to waiting: neither should dismiss the open-lock symbol. A second approval must restart the timer. Also check presenting a sheet and entering the background. Old reset work must not overwrite the newer display; returning to Home must not replay a past approval.
- Check rapid ordinary status changes: intermediate presentations lasting less than 300 ms should not flash. Approval, rejection, pause and connection errors must remain immediate, with matching text/icon/color; diagnostics must still show the live state.
- Check waiting-for-computer/service both display “正在搜索Windows电脑”, while diagnostics retain the original phases. Turn automatic response off without enrollment and confirm the waiting headline immediately becomes “自动响应已暂停”.
- Check low signal, automatic-response/eligibility rejection, RSSI read failure, authentication failure and transport failure: the five recognized codes must show their user messages instead of `unknown_result`. Low-signal text must be consistent before and after the Windows acknowledgment, with the original RSSI/threshold still visible in diagnostics. Confirm unrecognized results still produce an explicit error.
- Enable Reduce Motion and confirm symbol changes have no animated transition. Verify the native lock-symbol transition visually; its exact lock-shackle motion is system controlled.

## Acceptance after explicit build/test authorization

All commands below are relative to the repository root. They are instructions, not commands executed by the agent.

Pure policy tests:

```sh
swift test --package-path ./ios
```

Real iPhone and Windows:

1. Use the current Windows service/CP/tray build. Keep the native PIN/password path available. Do not clear the saved Windows password to troubleshoot this iOS change.
2. Open the Windows tray pairing/replacement flow on the unlocked desktop. In iOS choose Register/Re-register computer → Start registration, then confirm the same phone fingerprint in Windows. For an already registered key, use the existing confirmation outcome; do not regenerate the phone key.
3. Confirm iOS registration succeeded and ComputerId is present in Settings → Registration information and diagnostics. The connection may subsequently wait because Windows only advertises on lock or during pairing.
4. After registration, leave Windows on the unlocked desktop long enough to exceed the old recovery windows (at least one minute). Put iOS in the background and do not reopen it or tap Retry. Lock Windows, press Enter on the tile once, and confirm the phone becomes Ready, takes a new RSSI/signature, receives `unlock_approved`, and Windows actually unlocks. Compare SID/session with the pre-lock baseline. The Windows request still has its own 30-second deadline; slower discovery is not an RSSI failure.
5. Repeat at least five lock/unlock cycles, including unlocked-desktop gaps with the phone left in the background. Service absence must enter passive waiting; a service-change event must restore discovery without requiring foreground re-entry. A real initialization or RSSI callback timeout must report its phase while preserving future waiting, without a reconnect storm.
6. Restart the Windows tray and lock again. ComputerId must remain unchanged; if peripheral UUID changes, the existing iPhone target must still reconnect without re-registration.
7. Test below/above the RSSI threshold, a missing/invalid reading, full disconnection, explicit automatic off, and restoration after on. No stale reading or old result may approve a new request.
8. Test short background, phone locked background, Windows restart and subsequent native first login/lock, then overnight standby. Force-quitting the app is not a promised automatic-restoration path.
9. If iOS is Ready but Windows still waits, capture tray subscriptions/challenge delivery and service status. Do not infer an RSSI problem from a missing connection or an enrollment result.

The tests added cover production policy transitions, untimed remembered-target waiting, fixed unknown-candidate/initialization deadlines, passive service wait, event-driven recovery after exhaustion, late discovery draining, scan-round deduplication, new UUID admission, bounded candidate history, both subscriptions and stale authentication isolation. Existing identity, result, enrollment and preference tests remain. These tests do not simulate native callback delivery/cancellation or prove background/overnight reliability.

Capture both sides' timing: Windows broadcast start/stop and challenge delivery; iOS scan round, connection, service absence/change, subscription readiness and authentication result. If Windows service re-publication does not produce a usable CoreBluetooth event while waiting, report that evidence and stop expanding this iOS change. Do not add unlimited polling or silently change Windows advertising. Full pairing cancellation and Windows failure acceptance remain pending. No target-record migration or new registration is required for this revision's existing ComputerId records; the earlier UUID-only migration requirement still applies.

## References

- [Apple: peripheral(_:didModifyServices:)](https://developer.apple.com/documentation/corebluetooth/cbperipheraldelegate/peripheral(_:didmodifyservices:))
- [Apple: service-filtered scanning](https://developer.apple.com/documentation/corebluetooth/cbcentralmanager/scanforperipherals(withservices:options:))
- [Apple: Core Bluetooth background processing](https://developer.apple.com/library/archive/documentation/NetworkingInternetWeb/Conceptual/CoreBluetooth_concepts/CoreBluetoothBackgroundProcessingForIOSApps/PerformingTasksWhileYourAppIsInTheBackground.html)
- [Apple: What’s new in SwiftUI — SF Symbols 6 and Magic Replace](https://developer.apple.com/videos/play/wwdc2024/10144/)
