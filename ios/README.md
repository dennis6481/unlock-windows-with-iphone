<!-- Created by Rui MA on 03 Oct 2026 -->

# iOS developer guide

The iPhone app uses SwiftUI, CoreBluetooth and CryptoKit/Secure Enclave to respond to Windows requests. It never stores the Windows password. 

## Build and install on a device

### Prerequisites

- An Mac with **Xcode 26 or later**.
- A physical iPhone running **iOS 26 or later**. The simulator supports UI previews only; authentication requires Secure Enclave hardware.

1. Open [ios.xcodeproj](ios.xcodeproj) in Xcode and select the `ios` app scheme.
2. In **Signing & Capabilities**, choose your own development team for Debug and Release and enable automatic signing. Replace the checked-in bundle identifier (`com.ruima.unlock-windows`) with a unique identifier your team can sign. The checked-in team is not a distribution entitlement for other developers.
3. Connect and trust the iPhone, enable Developer Mode if requested, select it as the run destination, and build/run the app. Follow the device's development-app trust prompts where applicable. Signing validity and renewal depend on your Apple account/provisioning.
4. Grant Bluetooth permission. Xcode project settings generate the Bluetooth usage description. The minimal, Xcode-managed Info.plist supplies only the `bluetooth-central` background mode array.
5. Install Windows from the same repository revision and register the computer as described below.


## Unsigned IPA

The [Release workflow](../.github/workflows/release.yml) builds `UnlockPC_<tag>_unsigned.ipa` and publishes it alongside the Windows installers from the same tagged revision. The IPA must be signed with your own Apple development credentials and provisioning before installation; it cannot be installed directly. Signing and device operation have not been validated by CI.


## Register and use

1. On the unlocked Windows desktop open tray **Status…**, select **Pair iPhone** and approve UAC.
2. In the app select **Add a Windows PC**, then **Continue**. Compare the full iPhone fingerprint and confirm the target account on Windows. The phone waits for the Windows result before showing pairing success.
3. Complete registration only after a successful Windows enrollment result and a valid ComputerId. Cancelling, rejection or service reload failure preserves the previous valid phone target.
4. The phone always responds automatically to eligible requests from its paired PC. Lock Windows and press Enter / Unlock on the phone tile. The phone requires a new signal reading for each challenge before signing.

The app stores one registered computer record: its ComputerId, display name and last peripheral UUID. The name is display text; the peripheral UUID is a routing cache. A changed peripheral UUID alone does not require registration again. If Windows loses its ComputerId, register explicitly again.

Tap **Add a Windows PC**, then **Continue** to begin pairing and compare the full fingerprint with Windows. **Cancel Pairing** or going back from the verification page cancels pairing. On the cancellation page, choose **Done** to close or **Retry Pairing** to try again.

The app automatically responds to eligible unlock requests. On Home, adjust **Unlock Distance** from −100 to −20 dBm. Signal strength estimates proximity, not an exact distance. **Settings** provides the Privacy Policy, Diagnostics and app version/build. The interface is currently English only.

To register another PC, first choose **Remove Paired PC**, then add it from the empty home page. Removal forgets the target only on this iPhone, stops its pending operations and clears request history. Remove the iPhone authorization separately on Windows. The phone key and RSSI threshold are retained.

**Request approved** appears for up to five seconds on Home. **Last approval** shows the latest completed request’s approval time and signal strength in dBm, retained across app restarts. Failed requests or no result show **N/A**. Approval does not confirm that Windows completed unlocking.

## Directory structure

```text
ios/
├── MyApp.swift                         App entry point and lifecycle forwarding.
├── AppTabView.swift                    Tabs and navigation.
├── UI/
│   ├── HomeView.swift                  Paired PC status and unlock distance.
│   ├── UnpairedHomeView.swift          Home page before pairing.
│   ├── EnrollmentView.swift            Pairing flow.
│   └── SettingsView.swift              Settings and diagnostics.
├── Core/
│   ├── UnlockSetupModel.swift          App model and user actions.
│   ├── BluetoothAuthenticator.swift    CoreBluetooth operations and published state.
│   ├── BluetoothConnectionRecovery.swift Connection routes, cancellation and retries.
│   ├── BluetoothAuthenticationState.swift Readiness and per-request signal state.
│   ├── UnlockProtocol.swift            Protocol decoding and signing payload.
│   ├── SecureEnclaveKeyStore.swift     Key creation, persistence and signing.
│   └── UnlockError.swift               Error descriptions.
└── iosTests/                           Policy tests independent of BLE and Secure Enclave.
```

Wire formats and identity rules live in [PROTOCOL.md](../PROTOCOL.md); security assumptions live in [SECURITY.md](../SECURITY.md).

## Connection and recovery

- Connection setup verifies the paired PC and subscribes to challenge/result notifications within ten seconds after selecting a connected device.
- Service changes trigger rediscovery. **Retry** starts a new recovery cycle; Bluetooth interruptions preserve the paired PC record.
- Background reconnection depends on iOS and is not guaranteed after force-quitting the app.
- Each unlock request requires a fresh signal reading and signature within three seconds. Reconnection does not extend Windows' authentication deadline.
- The default signal threshold is −60 dBm. Signal strength estimates proximity, not an exact distance.

## Diagnostics and tests

Settings → Diagnostics retains up to 64 recent entries with UTC/monotonic time, connection generation, route attempt, peripheral/native state, requestID, RSSI and raw errors. Passwords, private keys, nonces and signature bodies are not diagnostic output.

In Xcode, select the `ios` scheme and choose **Product → Test** (`⌘U`).

These policy tests do not simulate native CoreBluetooth callback delivery, cancellation, radio behavior or Secure Enclave operation. Follow the [device and background testing guide](../docs/Testing.md) to validate actual behavior.

## References

- [Apple: Xcode 27 release notes and host requirements](https://developer.apple.com/documentation/xcode-release-notes/xcode-27-release-notes)
- [Apple: Secure Enclave key protection](https://developer.apple.com/documentation/security/protecting-keys-with-the-secure-enclave)
- [Apple: Core Bluetooth background processing](https://developer.apple.com/library/archive/documentation/NetworkingInternetWeb/Conceptual/CoreBluetooth_concepts/CoreBluetoothBackgroundProcessingForIOSApps/PerformingTasksWhileYourAppIsInTheBackground.html)
- [Apple: Service invalidation callback](https://developer.apple.com/documentation/corebluetooth/cbperipheraldelegate/peripheral(_:didmodifyservices:))
