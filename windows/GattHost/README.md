<!-- Created by Rui MA on 26 Sep 2026 -->

# Tray and GATT transport

`GattHost` runs inside the no-argument, ordinary-user role of `UnlockWithIPhone.exe`. It owns the host lifecycle, physical-console monitoring, BLE publication and pairing transport. It does not hold a password or create trusted approval. Role dispatch and startup are documented in the [Windows guide](../README.md#desktop-app-roles); wire messages are defined in [PROTOCOL.md](../../PROTOCOL.md#ble-messages).

`DesktopApp/TrayManager` handles the Win32 tray through menu-state, command and diagnostic callbacks. The host retains its HWND and controls shutdown; Quit posts an asynchronous close after the menu is released. Unhandled messages return `std::nullopt`; handled messages return their Windows result.

## Lock-aware publication

Session/power notifications trigger reconciliation with the physical console's actual `WTSSessionInfoEx` state. Publication requires an explicitly locked current console, except for a user-started pairing window on the unlocked desktop. First sign-in uses native Windows authentication.

Callbacks are marshalled to the control thread. The advertising lifecycle separates the requested target, raw WinRT status and accepted start/stop calls. A successful stop does not wait for a stale Started property to change, and cannot suppress the next lock's start. Startup is bounded and retries are limited; unlock, sleep and exit cancel pending retries.

Stopping publication does not proactively close BLE. Remote service loss can still invalidate characteristics and subscriptions. `unlock_approved` does not itself stop advertising: the host reconciles actual Windows session state.

## Authentication transport

The host peeks at service status through the phone-only pipe. It selects the unique connection subscribing to challenge and result, sends a readiness probe, checks the current connection/request receipt, then takes the challenge once. Preparation cannot consume or extend the request. Assertions are forwarded unchanged to LocalSystem for verification; no credential-claim operation is exposed here.

The target user's persistent ComputerId identifies the configured computer. The name/peripheral UUID is not authority. Pairing mode excludes authentication request/assertion handling. Disconnect, generation changes and request completion invalidate stale preparation.

## Pairing

1. On the unlocked console choose **Pair iPhone…**. The tray requests UAC once and launches the same EXE's elevated enrollment role.
2. After the restricted local channel reports that the tool is ready, the tray advertises for registration. Start registration in the iOS app.
3. Confirm the actual console account and the full eight-group SHA-256 phone fingerprint in the Windows window. Another administrator's UAC credentials do not change the target user.
4. A matching key/SID is already registered: confirmation reloads the service without rewriting the file. A different phone needs explicit replacement confirmation.

The two-minute deadline begins at the initiating click, including UAC time. Cancellation, timeout, disconnection, lock, session change, sleep or tray exit terminates pairing. The enrollment code rechecks console state, authority, cancellation, parent liveness and the original record before committing.

Registration is validated as a P-256 point, written to a protected same-directory temporary file, flushed and atomically replaced. Failure before commit preserves the previous record. A post-commit service reload failure explicitly reports saved/removed-but-not-loaded; it does not claim rollback. The public-key record uses machine-scope DPAPI and protected ACLs; it is distinct from the password vault.

## Continue setup

**Continue setup…** reuses the elevated password-management window, then the existing pairing workflow. A confirmed password-ready result is required before pairing. Existing credentials and matching registration skip completed steps; UAC cancellation, window closure and failures stop the sequence. The ordinary tray rechecks the initiating console before continuing and serializes repeated setup requests. Completion prompts ask for a lock-screen test rather than claiming successful native authentication.

## Tray actions and maintenance

| Action | Effect |
|---|---|
| Status… | Current registration, connection/publication state, Refresh and technical diagnostics. |
| Pair iPhone… | First enrollment, already-registered confirmation or explicit phone replacement. |
| Manage saved password… | Elevated password-management role in a separate instance. |
| Remove paired iPhone… | Removes registration and reloads the service; does not remove the password, ComputerId or OS Bluetooth pairing. |
| Quit | Stops publication, cancels pairing/async work and releases events/resources. |

The ordinary tray refuses elevated execution. Closing an operation window leaves the tray running. Historical errors stay available in details without overriding a recovered current state. A missing taskbar triggers bounded work within the tray rather than process-restart loops.

Use the [testing guide](../../docs/Testing.md#connection-and-background-recovery) for repeated locking, background recovery and failure checks. Do not run an additional build-tree host alongside an installed instance.

## References

- [Microsoft GATT foreground sample](https://github.com/microsoft/Windows-universal-samples/blob/main/Samples/BluetoothLE/cppwinrt/Scenario3_ServerForeground.cpp)
- [WTS session notifications](https://learn.microsoft.com/en-us/windows/win32/api/wtsapi32/nf-wtsapi32-wtsregistersessionnotification)
- [WTSINFOEX lock state](https://learn.microsoft.com/en-us/windows/win32/api/wtsapi32/ns-wtsapi32-wtsinfoex_level1_w)
