<!-- Created by Rui MA on 03 Oct 2026 -->

# iOS Bluetooth unlock

## Current status

2026-10-03: the user reported a regression after commit `70ca5eb`: repeated GATT service invalidation, forced disconnect/reconnect, and no unlock. The forced disconnect is a concrete new code path and a regression suspect, not a proven explanation for every Windows/iOS failure. This revision changes that path and redesigns the UI. Only static inspection has been performed; no build, test execution, installation, or device acceptance has been performed.

Windows remains the authentication authority. The flow is an existing locked console session → Enter on the phone tile → a fresh RSSI/signature response → Windows approval → CP automatic submission. The iPhone does not store the Windows password. `unlock_approved` means approval, not confirmed desktop unlock.

## Connection and recovery

- `BluetoothAuthenticationState` is the production initialization/RSSI policy also exercised by the pure Swift tests. `BluetoothAuthenticator` owns CoreBluetooth operations and publishes one structured snapshot; the model does not overwrite connection status with enrollment/authentication strings.
- Only a verified computer identity and both challenge/result subscriptions establish Ready. Merely connecting does not reset the retry budget or authorize signing.
- Service invalidation discards old characteristics and the pending authentication, then rediscovers on the same connection. Discovery operations are serialized; repeated invalidations request a coalesced follow-up pass without extending the existing deadline.
- Connection attempts and service initialization each have a fixed 10-second window. A failed recovery permits at most one additional connection attempt; complete Ready resets that budget. Foreground re-entry, Bluetooth state changes, or explicit retry can begin a new bounded attempt. There is no unbounded timer retry loop.
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

- Home shows connection, enrollment and authentication separately, with actionable states and a recent authenticated-request RSSI timestamp.
- Removed constant Connect/Stop buttons and manual key preparation, local signature testing and raw public-key clipboard actions.
- Registration uses its own sheet: Start registration, Cancel registration while active, Finish afterwards. The Windows fingerprint must still be confirmed locally.
- Retry connection appears on failure; it does not re-enroll or create Windows approval.
- Automatic response defaults to on. Preference version 2 silently turns it on once on upgrade; subsequent explicit user changes are preserved. Disconnect, missing target, Bluetooth failure and enrollment failure do not change or disable the toggle.
- Recent diagnostics retain at most 64 entries: controlled phases, timings, subscription flags, RSSI, bounded recovery and allowlisted result codes. No passwords, keys, candidate public-key data, nonces or signature bodies are logged.

## Acceptance after explicit build/test authorization

All commands below are relative to the repository root. They are instructions, not commands executed by the agent.

Pure policy tests:

```sh
swift test --package-path ./ios
```

Real iPhone and Windows:

1. Use the current Windows service/CP/tray build. Keep the native PIN/password path available. Do not clear the saved Windows password to troubleshoot this iOS change.
2. Open the Windows tray pairing/replacement flow on the unlocked desktop. In iOS choose Register/Re-register computer → Start registration, then confirm the same phone fingerprint in Windows. For an already registered key, use the existing confirmation outcome; do not regenerate the phone key.
3. Confirm iOS registration succeeded and ComputerId is present in the diagnostics disclosure. The connection may subsequently wait because Windows only advertises on lock or during pairing.
4. Lock Windows. Wait for iOS Ready, press Enter on the Windows tile once, and confirm a new RSSI/signature and `unlock_approved` followed by actual desktop unlock. Compare SID/session with the pre-lock baseline.
5. Repeat lock/unlock. Service invalidation should rediscover rather than immediately disconnect repeatedly. A real initialization or RSSI callback timeout must report the specific reason.
6. Restart the Windows tray and lock again. ComputerId must remain unchanged; if peripheral UUID changes, the existing iPhone target must still reconnect without re-registration.
7. Test below/above the RSSI threshold, a missing/invalid reading, full disconnection, explicit automatic off, and restoration after on. No stale reading or old result may approve a new request.
8. Test short background, phone locked background, Windows restart and subsequent native first login/lock, then overnight standby. Force-quitting the app is not a promised automatic-restoration path.
9. If iOS is Ready but Windows still waits, capture tray subscriptions/challenge delivery and service status. Do not infer an RSSI problem from a missing connection or an enrollment result.

The tests added cover production policy transitions, fixed deadlines, coalesced invalidation, retry exhaustion, both subscriptions, ComputerId parsing/matching, stale RSSI/write generations, result request association, enrollment replacement decisions and preference migration. They do not simulate a full CoreBluetooth stack or prove background/overnight reliability. Full pairing cancellation and Windows failure acceptance remain pending.

## References

- [Apple: peripheral(_:didModifyServices:)](https://developer.apple.com/documentation/corebluetooth/cbperipheraldelegate/peripheral(_:didmodifyservices:))
- [Apple: service-filtered scanning](https://developer.apple.com/documentation/corebluetooth/cbcentralmanager/scanforperipherals(withservices:options:))
- [Apple: Core Bluetooth background processing](https://developer.apple.com/library/archive/documentation/NetworkingInternetWeb/Conceptual/CoreBluetooth_concepts/CoreBluetoothBackgroundProcessingForIOSApps/PerformingTasksWhileYourAppIsInTheBackground.html)
