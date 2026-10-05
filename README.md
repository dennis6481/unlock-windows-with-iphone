<!-- Created by Rui MA on 26 Sep 2026 -->

# Unlock with iPhone®

Unlock an existing Windows desktop session using a signature from your iPhone's Secure Enclave over Bluetooth Low Energy (BLE).

**Developer technical preview.** There is currently no App Store or TestFlight distribution for the iOS app: you need a Mac, Xcode and your own signing configuration to install it on a physical iPhone. This is an experimental open-source project, not a ready-to-use consumer release.



## What it does

- Registers one iPhone public key with the current Windows console account after fingerprint confirmation.
- Keeps the phone's signing private key in the Secure Enclave. The phone does not receive the Windows password.
- Stores an encrypted copy of the Windows Microsoft Account (MSA) password in a dedicated LocalSystem service.
- Uses a Credential Provider to submit that password to Windows' native authentication after a valid, one-time phone approval.
- Provides a Windows tray app for status, phone pairing and saved-password management, plus an installer for install, update and removal.

## The workflow

1. Install the Windows components, restart and sign in once using your usual Windows PIN/password.
2. On the verified installation result page, choose **Start setup**. Save the actual account password in the existing management window, then pair the iPhone and confirm its full fingerprint. **Continue setup…** in the tray resumes unfinished configuration.
3. Lock Windows and press **Enter / Unlock** on the phone credential tile.
4. The phone checks the registered computer, automatic-response setting and a fresh signal reading, then signs the request.
5. The Windows service verifies the signature; the Credential Provider submits the saved password and Windows performs the actual unlock.

Phone approval is automatic when its configured conditions are met; selecting the tile or merely being nearby does not create an approval. Restarting or signing out requires a native Windows sign-in before phone unlock is available again.

The [protocol and architecture](Protocol.md) describe the complete data flow and trust boundaries.

## Requirements

| Component | Requirement |
|---|---|
| Windows | Windows 10 version **1703, build 15063**, or later, including Windows 11. This is the API-derived minimum, not a tested compatibility matrix; see the [Windows compatibility notes](windows/README.md#compatibility). |
| Windows architecture | Native **x64 (64-bit x86)** or **ARM64**. ARM64 has not been tested on physical hardware. 32-bit x86 and ARM32 are not supported. |
| PC Bluetooth | BLE-capable adapter and driver with Windows GATT server / peripheral advertising support. BLE support alone does not guarantee that the adapter can publish this service. |
| Phone | Physical iPhone with **iOS 18 or later**, Bluetooth enabled and Secure Enclave available. |
| Windows account | An existing local console session with a password-backed Microsoft Account. Other account types and remote sessions are not established supported configurations. |
| Development | Windows C++ tools for the Windows components; a Mac and Xcode for the iPhone app. See the platform guides below. |

## Build and set up

- [Windows: prerequisites, build, installation and setup](windows/README.md)
- [iOS: Xcode signing, device installation and app settings](ios/README.md)
- [Testing and diagnostics](docs/Testing.md)

Build both platforms from the same revision. Do not mix service, Credential Provider and desktop binaries from different builds. A simulator can be useful for UI work, but cannot exercise the Secure Enclave signing path.

## Repository guide

| Location | Purpose |
|---|---|
| `ios/` | SwiftUI app, CoreBluetooth coordination, Secure Enclave signing and pure policy tests. |
| `windows/` | Desktop app, credential service, Credential Provider, installer, shared code and C++ tests. |
| [Protocol.md](Protocol.md) | Cross-platform protocol and overall architecture. |
| [SECURITY.md](SECURITY.md) | Credential protection, security assumptions and limitations. |
| [docs/Testing.md](docs/Testing.md) | Reproducible checks and release evidence requirements. |

The [Windows module index](windows/README.md#module-index) explains the source directories. Source modules are not separate installed programs.

## Known limitations

- **Distribution:** There is no iOS distribution channel; device installation and signing are the developer's responsibility. Production signing and distribution are not guaranteed.
- **Windows sessions and accounts:** Only an existing physical-console session can be unlocked. Initial sign-in after boot or sign-out uses the original Windows password/PIN path. The current credential integration targets password-backed MSA accounts; account changes or an outdated saved password can cause native authentication to fail.
- **Bluetooth and proximity:** Background BLE recovery depends on the iPhone, Windows adapter, driver and OS. Overnight operation, sleep/resume and failure scenarios need broader device testing. Force-quitting the iOS app is not a promised recovery path. RSSI is an adjustable proximity heuristic, not a reliable distance measurement or protection against relay attacks.
- **Validation and security assurance:** ARM64 hardware, the oldest supported Windows build and the full negative-path matrix have not been validated. There has been no independent security audit.

The testing guide describes how to report results without treating a successful normal-path trial as full acceptance.

## To Do

- [ ] Modernize the iOS and Windows UI and setup guidance
- [ ] Integrate iOS AccessorySetupKit.
- [ ] Move Windows installer packaging to an MSI architecture.
- [ ] Investigate LSA-based Windows authentication to replace the current implementation that stores a local Windows password copy.

## License and acknowledgements

The project uses the [MIT License](LICENSE.md). This is an independent project; product names identify the platforms it works with.

## References

- [Apple: Protecting keys with the Secure Enclave](https://developer.apple.com/documentation/security/protecting-keys-with-the-secure-enclave)
- [Apple: Core Bluetooth background processing](https://developer.apple.com/library/archive/documentation/NetworkingInternetWeb/Conceptual/CoreBluetooth_concepts/CoreBluetoothBackgroundProcessingForIOSApps/PerformingTasksWhileYourAppIsInTheBackground.html)
- [Microsoft: Credential Providers](https://learn.microsoft.com/en-us/windows/win32/secauthn/credential-providers-in-windows)
- [Microsoft: GATT server](https://learn.microsoft.com/en-us/windows/apps/develop/devices-sensors/gatt-server)

- [Microsoft: Credential Provider system user array](https://learn.microsoft.com/en-us/windows/win32/api/credentialprovider/nf-credentialprovider-icredentialprovidersetuserarray-setuserarray)
