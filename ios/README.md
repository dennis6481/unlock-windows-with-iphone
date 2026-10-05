<!-- Created by Rui MA on 03 Oct 2026 -->

# iOS developer guide

The iPhone app uses SwiftUI, CoreBluetooth and CryptoKit/Secure Enclave to respond to Windows requests. It never stores the Windows password. There is currently no App Store or TestFlight distribution: developers install it with their own Xcode signing configuration.

## Build and install on a device

- Use **Xcode 27** as the current project baseline, on an Apple silicon Mac with a macOS version supported by that Xcode release. The checked-in project records tools/upgrade version 27 and object version 90; opening/building it in older Xcode versions has not been verified. The source uses iOS 18 APIs, and the app deployment target remains **iOS 18.0**.
- Use a physical iPhone running iOS 18 or later. Secure Enclave availability is checked at runtime; there is no software-key fallback for the simulator.
- The separate Swift Package policy tests require **Swift 6.0 or newer**. The app target currently uses Swift 5 language mode; the package tools version is a distinct requirement.

1. Open [ios.xcodeproj](ios.xcodeproj) in Xcode and select the `ios` app scheme.
2. In **Signing & Capabilities**, choose your own development team for Debug and Release and enable automatic signing. Replace the checked-in bundle identifier (`com.ruima.unlock-windows`) with a unique identifier your team can sign. The checked-in team is not a distribution entitlement for other developers.
3. Connect and trust the iPhone, enable Developer Mode if requested, select it as the run destination, and build/run the app. Follow the device's development-app trust prompts where applicable. Signing validity and renewal depend on your Apple account/provisioning.
4. Grant Bluetooth permission. The app's Info.plist declares the Bluetooth usage description and `bluetooth-central` background mode.
5. Install Windows from the same repository revision and register the computer as described below.

The Home Screen name comes from `INFOPLIST_KEY_CFBundleDisplayName`; Info.plist references that setting. The in-app title is separate. No signing certificate, provisioning profile or private signing key is distributed in this repository.

## Register and use

1. On the unlocked Windows desktop select **Pair iPhone…** in the tray and approve UAC.
2. In the app select **登记电脑** (Register computer), or Settings → re-register, then start registration. Confirm the full fingerprint and target account on Windows.
3. Complete registration only after a successful Windows enrollment result and a valid ComputerId. Cancelling, rejection or service reload failure preserves the previous valid phone target.
4. Keep automatic response enabled in Settings. Lock Windows and press Enter / Unlock on the phone tile. The phone requires a new signal reading for each challenge before signing.

The app stores one registered computer record: its ComputerId, display name and last peripheral UUID. The name is display text; the peripheral UUID is a routing cache. A changed peripheral UUID alone does not require registration again. If Windows loses its ComputerId, register explicitly again.

The automatic-response preference remains off when saved as off. Bluetooth interruptions, disconnection and registration errors do not silently change it. Settings also expose the signal threshold, registration metadata, diagnostics and Retry. The iOS UI currently includes Chinese text.

## Code responsibilities

| Source | Responsibility |
|---|---|
| `MyApp.swift`, `ContentView.swift` | Lifecycle forwarding and SwiftUI presentation. |
| `Core/UnlockSetupModel.swift` | App model and user actions. |
| `Core/BluetoothAuthenticator.swift` | Native CoreBluetooth operations and structured published state. |
| `Core/BluetoothConnectionRecovery.swift` | Per-peripheral pending/connected routes, cancellation and retry policy. |
| `Core/BluetoothAuthenticationState.swift` | Selected-connection initialization, readiness and per-request RSSI state. |
| `Core/UnlockProtocol.swift` | Protocol decoding and canonical signing payload. |
| `Core/SecureEnclaveKeyStore.swift` | Secure Enclave key creation, keychain persistence and signing. |
| `Tests/`, `Package.swift` | Pure policy regression tests, independent of native BLE and Secure Enclave. |

Wire formats and identity rules live in [Protocol.md](../Protocol.md); security assumptions live in [SECURITY.md](../SECURITY.md).

## Connection and recovery

Service-filtered scanning can track up to sixteen native routes, including restored pending connections. A system-owned pending connection has no application timeout. A fresh advertised candidate may connect while an older route remains pending; only an actually connected candidate takes the single GATT initialization slot.

Initialization requires ComputerId verification and both challenge/result notification subscriptions. Its monotonic ten-second deadline starts when the connected candidate is selected, not while CoreBluetooth is merely waiting to connect. Foreground entry and relevant callbacks check the deadline directly, so a timer delayed by suspension cannot authorize expired readiness. Each route has one active retry; restarting a scan alone does not replenish an exhausted cached route.

Service changes invalidate characteristics and pending authentication, then trigger serialized rediscovery. A confirmed missing service releases that connection and waits for fresh service advertising instead of immediately reconnecting the cache. Healthy usable connections are retained. Cancellation drains the old native terminal callback before reconnecting the same peripheral; late callbacks are checked against connection and generation.

Foreground entry reconciles missing operations. Explicit Retry can start a new recovery cycle. Automatic response off and Bluetooth unavailable stop operations without changing the saved preference. Background restoration depends on native OS scheduling and is not guaranteed after force-quitting the app.

Each challenge requires a fresh RSSI read and signature within three seconds; old displayed readings are not reused. Waiting for the Windows result after sending a signature is a separate phase. The adjustable threshold defaults to −60 dBm and does not promise a fixed distance. Readiness and reconnects do not extend Windows' authentication deadline.

## Diagnostics and tests

Settings diagnostics retain up to 64 recent entries with UTC/monotonic time, connection generation, route attempt, peripheral/native state, requestID, RSSI and raw errors. Passwords, private keys, nonces and signature bodies are not diagnostic output. Redact personal machine/device identifiers before sharing logs publicly.

From the repository root:

```sh
swift test --package-path ./ios
```

These policy tests do not simulate native CoreBluetooth callback delivery, cancellation, radio behavior or Secure Enclave operation. Follow the [device and background testing guide](../docs/Testing.md) to validate actual behavior.

## References

- [Apple: Xcode 27 release notes and host requirements](https://developer.apple.com/documentation/xcode-release-notes/xcode-27-release-notes)
- [Apple: Secure Enclave key protection](https://developer.apple.com/documentation/security/protecting-keys-with-the-secure-enclave)
- [Apple: Core Bluetooth background processing](https://developer.apple.com/library/archive/documentation/NetworkingInternetWeb/Conceptual/CoreBluetooth_concepts/CoreBluetoothBackgroundProcessingForIOSApps/PerformingTasksWhileYourAppIsInTheBackground.html)
- [Apple: Service invalidation callback](https://developer.apple.com/documentation/corebluetooth/cbperipheraldelegate/peripheral(_:didmodifyservices:))
