<!-- Created by Rui MA on 26 Sep 2026 -->

# Tray and GATT transport

`GattHost` runs on a background MTA control thread inside the ordinary-user desktop role of `UnlockWithIPhone.exe`. It owns physical-console monitoring, BLE publication and pairing transport. It does not hold a password or create trusted approval. Role dispatch and startup are documented in the [Windows guide](../README.md#desktop-app-roles); wire messages are defined in [PROTOCOL.md](../../PROTOCOL.md#ble-messages).

`DesktopApp/DesktopHost` runs the WinUI application and `TrayManager` on the main STA. The public tray HWND handles activation and maintenance exit requests; the private MTA HWND alone handles session/power events and the GATT control timer. The control window is ready before the tray is created, without waiting for GATT initialization. Commands use the existing callback queue; snapshots return to the STA. Tray registration retries and Explorer recovery stay on the STA. Unhandled tray messages return `std::nullopt`; handled messages return their Windows result.

Quit closes callback admission before cancelling pairing and cleaning up GATT. Late Helper callbacks are rejected; ending the control thread does not mean detached Helper waits have ended. The STA observes the control thread handle before joining and exiting WinUI. Dispatcher rejection is logged, with a STA timer observing saved updates. After ten seconds without completion, exit is reported incomplete and the app remains responsive until cleanup finishes; it does not force termination.

Snapshots are published after initialization, each control dispatch batch and session/power handling. UI errors stay in the shared diagnostic history without replacing the last communication error; UI reports arriving after shutdown begins do not enqueue dialogs. Normal Quit returns `0`; terminal control-thread failures return `1`.

## Lock-aware publication

Session/power notifications trigger reconciliation with the physical console's actual `WTSSessionInfoEx` state. Publication requires an explicitly locked current console, except for a user-started pairing window on the unlocked desktop. First sign-in uses native Windows authentication.

Callbacks are marshalled to the control thread. The advertising lifecycle separates the requested target, raw WinRT status and accepted start/stop calls. A successful stop does not wait for a stale Started property to change, and cannot suppress the next lock's start. Advertising startup is bounded and retries are limited; unlock, sleep and exit cancel pending retries.

Stopping publication does not proactively close BLE. Remote service loss can still invalidate characteristics and subscriptions. `unlock_approved` does not itself stop advertising: the host reconciles actual Windows session state.

## Authentication transport

The host peeks at service status through the phone-only pipe. It selects the unique connection subscribing to challenge and result, sends a readiness probe, checks the current connection/request receipt, then takes the challenge once. Preparation cannot consume or extend the request. Assertions are forwarded unchanged to LocalSystem for verification; no credential-claim operation is exposed here.

The target user's persistent ComputerId identifies the configured computer. The name/peripheral UUID is not authority. Pairing mode excludes authentication request/assertion handling. Disconnect, generation changes and request completion invalidate stale preparation.

## Pairing

1. On the unlocked console open tray **Status…** and choose **Pair iPhone**. The tray requests UAC once and launches the same EXE's elevated enrollment role.
2. After the restricted local channel reports that the tool is ready, the tray advertises for registration. Start registration in the iOS app.
3. Confirm the actual console account and the full eight-group SHA-256 phone fingerprint in the Windows window. Another administrator's UAC credentials do not change the target user.
4. A matching key/SID is already registered: confirmation reloads the service without rewriting the file. A different phone needs explicit replacement confirmation.

The two-minute deadline begins at the initiating click, including UAC time. Cancellation, timeout, disconnection, lock, session change, sleep or tray exit terminates pairing. The enrollment code rechecks console state, authority, cancellation, parent liveness and the original record before committing.

Registration is validated as a P-256 point, written to a protected same-directory temporary file, flushed and atomically replaced. Failure before commit preserves the previous record. A post-commit service reload failure explicitly reports saved/removed-but-not-loaded; it does not claim rollback. The public-key record uses machine-scope DPAPI and protected ACLs; it is distinct from the password vault.

## Continue setup

**Start setup** from the installation result, or `--setup`, opens the elevated WinUI password window, then the existing pairing workflow. A confirmed password-ready result is required before pairing. Existing credentials and matching registration skip completed steps; UAC cancellation, window closure and failures stop the sequence. The ordinary tray rechecks the initiating console before continuing and serializes repeated setup requests. Completion prompts ask for a lock-screen test rather than claiming successful native authentication. For manual setup, save the password on **Password**, then pair on **Status**.

## Tray actions and maintenance

| Action | Effect |
|---|---|
| Left click | Shows the existing main window and current page; first opening selects Status. |
| Status… | Opens the Status page; pairing and phone removal remain page actions. |
| Password… | Opens verified account/password status; saving, updating and removal request elevation only when selected. |
| About… | Opens product information and manual release checks. |
| Quit | Stops publication, cancels pairing/async work and releases events/resources. |

The ordinary tray refuses elevated execution. Closing an operation window leaves the tray running. Historical errors stay available in details without overriding a recovered current state. A missing taskbar triggers bounded work within the tray rather than process-restart loops.

Use the [testing guide](../../docs/Testing.md#connection-and-background-recovery) for repeated locking, background recovery and failure checks. Do not run an additional build-tree host alongside an installed instance.

## References

- [Microsoft GATT foreground sample](https://github.com/microsoft/Windows-universal-samples/blob/main/Samples/BluetoothLE/cppwinrt/Scenario3_ServerForeground.cpp)
- [WTS session notifications](https://learn.microsoft.com/en-us/windows/win32/api/wtsapi32/nf-wtsapi32-wtsregistersessionnotification)
- [WTSINFOEX lock state](https://learn.microsoft.com/en-us/windows/win32/api/wtsapi32/ns-wtsapi32-wtsinfoex_level1_w)
