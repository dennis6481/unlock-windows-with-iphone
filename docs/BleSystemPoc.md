<!-- Created by Rui MA on 10 Oct 2026 -->

# iPhone system BLE feasibility PoC

The standalone LocalSystem diagnostic shares system BLE operations with the app-free presence implementation. It is not installed and cannot request or perform Windows unlock. Historical hardware evidence below permits product implementation; remaining scenarios are delivery/enablement acceptance conditions.

## Run

### LocalSystem / Session 0 prerequisite

`windows/MSBuild/UnlockSystemBleDiagnostic.vcxproj` remains a separate diagnostic target, excluded from the installer and normal product builds. It shares contracts/operations but makes no credential, binding-management or approval IPC calls.

Build only when explicitly requested, using the existing toolchain:

```powershell
$diagnosticBuild = Join-Path (Get-Location) 'windows/build/system-ble-diagnostic'
& './windows/WindowsBuild.ps1' -InvokeMSBuild './windows/MSBuild/UnlockSystemBleDiagnostic.vcxproj' -TargetArchitecture x64 /m:1 /nologo /p:Configuration=Debug "/p:UnlockBuildDirectory=$diagnosticBuild"
```

After building, run `unlock_system_ble_diagnostic.exe --list` as the signed-in console user. Select the **system container GUID** shared by exactly one paired Classic and one paired BLE endpoint. Missing or ambiguous system relationships block the test; matching names or guessing an address is not supported. Device names, container IDs and endpoint IDs in diagnostic output are personal identifiers: redact them before sharing.

With explicit permission to install/run a temporary diagnostic service, use an elevated PowerShell window:

```powershell
$diagnosticExe = (Resolve-Path './windows/build/system-ble-diagnostic/unlock_system_ble_diagnostic.exe').Path
$diagnosticContainer = '{REPLACE-WITH-SYSTEM-CONTAINER-GUID}'
$diagnosticImage = '"{0}" --service "{1}"' -f $diagnosticExe, $diagnosticContainer
New-Service -Name 'UnlockWindowsSystemBleDiagnostic' -BinaryPathName $diagnosticImage -StartupType Manual
Start-Service -Name 'UnlockWindowsSystemBleDiagnostic'
```

The default service account is LocalSystem; the diagnostic also verifies its actual token and Session 0. It waits ten seconds so the operator can lock the PC/phone, then performs one request with a 30-second deadline and stops. Logs append to `SystemBleDiagnostic.log` beside the EXE. A failed run uses a nonzero SCM service-specific exit code; use `sc.exe query UnlockWindowsSystemBleDiagnostic` and inspect the log. Log-open failures are reported to SCM and debugger output. No consent UI, desktop-success report or cached GATT result can substitute for a service result.

Before testing independent service access, exit the Windows desktop application using tray **Quit**. Closing its window only hides it; the old embedded BLE probe has been removed. The product service now retains BLE independently of the desktop: stop it in an explicitly authorized diagnostic environment to avoid sharing an existing product connection.

For another RSSI threshold, append the integer to `$diagnosticImage`, for example `--service "{GUID}" -70`, before creating the service. The supported range/default come from `SystemBleContract.h`; the production saved threshold does not change this temporary service's arguments. This is not a persisted product setting.

The request requires authenticated Secure Connections bond metadata, Windows-cached ANCS/CCCD structure queries, protected notification subscription, protected **Uncached CCCD read**, successful unsubscribe and fresh address/type-associated RSSI above threshold. Missing/stale RSSI waits within the original deadline; fresh low signal fails. Evidence expires after three seconds. No notification payload is read. `PASS` applies only to this one-shot session, which closes afterward; current-link LESC mode/key reuse, phone user intent and physical distance remain unattested. Stop, console/power events, disconnect, GATT changes after complete protected verification, timeout and callback/logging errors invalidate the run. If connection cancellation or cleanup remains pending at the deadline, the process exits with failure and does not retry.

During initial ANCS discovery and protected verification, [GattServicesChanged](https://learn.microsoft.com/en-us/uwp/api/windows.devices.bluetooth.bluetoothledevice.gattserviceschanged) marks the provisional result as stale. The shared implementation discards it and repeats structure discovery within the original deadline. A stable non-success result still fails; rediscovery never extends the deadline or accepts stale evidence. Historical results below predate Cached-mode structure queries, retained product connections and RSSI waiting; those changes have static inspection only.

Restart the one-shot service with `Start-Service` for each scenario below. Stop with `Stop-Service` if still running; remove the temporary registration with `sc.exe delete UnlockWindowsSystemBleDiagnostic` after it stops. These actions are not performed automatically by the diagnostic or product installer.

| Required acceptance scenario | Expected evidence |
| --- | --- |
| PC unlocked, iPhone unlocked; custom iOS app absent | LocalSystem=1, session=0, unique system association, protected live operations and fresh RSSI pass. |
| PC locked, iPhone locked/screen off | Same success without interactive consent or waking the phone; console SessionFlags=0. |
| iPhone Bluetooth disabled in Settings / phone out of range | Failure; cached discovery or old samples never produce PASS. |
| Bluetooth enabled again after observed disconnection | A new run succeeds with fresh operations/samples. |
| Diagnostic service restarted, then PC rebooted and natively signed in | New runs resolve the same system binding and succeed. |
| Same-name second phone / absent or ambiguous container / pairing removed | Selected target cannot silently change; failure when its valid binding is unavailable. |
| Threshold raised above received RSSI / stale or missing samples | Failure with the relevant RSSI reason. |
| Stop, unlock, logoff, console change or suspend during a request | Invalidated/failed; no late success. |

Record OS/iOS versions, adapter/driver, revision, scenario and per-run result. One PASS does not complete the matrix. **Current status: no-app LocalSystem / Session 0 PASS with the PC locked and phone locked/screen off, desktop app exited and no manual phone connection. iPhone Bluetooth-off and below-threshold RSSI were rejected; the remaining acceptance matrix is pending.** Remaining scenarios are acceptance conditions for delivery and enablement, not a reason to retain the removed signature path.

## Evidence and states

Recorded on 10 Oct 2026:

- **Earlier revision passed:** x64 Debug desktop build of the original Central-only probe and WinUI integration; zero warnings/errors. The slider has only static validation; the updated diagnostic was built and run by the user. No installer was built or run by this change.
- **Build environment failure, resolved:** online NuGet restore failed with NU1301; restore succeeded using the existing `windows/DesktopApp/packages` cache as `RestoreSources` with `NuGetAudit=false`. Normal build then succeeded. This is not a BLE feasibility result.
- **User-reported desktop evidence:** Windows Settings pairing made the BLE target discoverable. Bond protection=3 and Secure Connections pairing=yes; uncached ANCS/Notification Source discovery and protected CCCD subscribe/unsubscribe succeeded repeatedly; address-associated RSSI was observed. The publisher reached Started without an API error. These are desktop observations, not LocalSystem results or proof of a new physical connection between attempts.
- **Earlier service failures:** runs confirmed LocalSystem/Session 0, a unique Classic/BLE container association and authenticated Secure Connections bond metadata, then failed with ANCS Unreachable or initial GattServicesChanged invalidation. They recorded console SessionFlags=1 (unlocked).
- **User-reported service PASS (pid=372):** the corrected diagnostic discarded the initial changed snapshot, then completed stable ANCS/Notification Source/CCCD discovery, protected subscribe, protected Uncached CCCD read and unsubscribe. RSSI=-58 dBm with age=1047 ms exceeded the -60 dBm threshold; SCM reported success within about 4.9 seconds. LocalSystem=1, session=0 and console SessionFlags=1. Phone screen state, no-app condition and platform details were not recorded in this log.
- **User-reported locked-console PASS (pid=24900):** LocalSystem=1, session=0 and console SessionFlags=0. Stable discovery, protected CCCD subscribe, Uncached read and unsubscribe succeeded; RSSI=-58 dBm with age=31 ms. SCM reported success within about 4.6 seconds. The user confirmed the PC was locked; phone screen state and no-app condition remain unrecorded.
- **User-confirmed no-app locked/screen-off PASS (pid=6872):** LocalSystem=1, session=0 and console SessionFlags=0. Protected subscribe, Uncached CCCD read and unsubscribe succeeded; RSSI=-43 dBm with age=922 ms. SCM reported success within about 5.3 seconds. The user confirmed the phone stayed locked/screen off, the custom iPhone app was absent, the Windows desktop app had fully exited through tray Quit and no manual phone connection was made.
- **User-reported Bluetooth-off rejection (pid=23252):** the user disabled iPhone Bluetooth in Settings. The unlocked-PC LocalSystem run still resolved the bond but returned stable ANCS status=1, connection status=0 and service count=0, then FAIL and SCM failure within about 7.8 seconds. No protected operation or RSSI success was reported; the prior PASS did not carry over.
- **User-reported phone-locked RSSI rejection (pid=6572):** the user confirmed the phone was locked; the PC recorded SessionFlags=1. BLE connected and stable discovery, protected subscribe, Uncached CCCD read and unsubscribe succeeded. Fresh RSSI=-66 dBm with age=0 ms was below the -60 dBm threshold. The complete log confirms RSSI below threshold and SCM failure; screen-off state and any manual reconnection actions were not recorded for this run.
- **Not established:** app-initiated first pairing, current-link LESC/key reuse, repeatable recovery, sleep/resume, reboot and the remaining gate matrix. Platform details must be recorded with the service-context evidence.

| Observation | Meaning |
| --- | --- |
| Not Paired / Paired | Windows bond status, separate from current-link authentication. |
| ANCS advertising requested / Started / failed | Publisher request/status only; not evidence of a connectable ANCS solicitation or phone-initiated pairing. |
| Connecting / Connected | Connection attempt / link status only. |
| Numeric Comparison confirmed | This run received `ConfirmPinMatch` and the user confirmed it. Existing bonds have no ceremony evidence in this run. |
| Secure Connections used for pairing | Windows bond metadata; not a current-link security measurement. |
| Protected GATT request succeeded | ANCS Notification Source CCCD subscription requested `EncryptionAndAuthenticationRequired` and returned success. Notifications are immediately unsubscribed; payloads are never consumed. |
| Authentication Failed | Pairing, service access, protected operation or link failed. Raw status, ATT error or HRESULT is logged. |
| Authenticated | **Unverified** for the full current LESC requirement. This probe has no current-link LESC/key-reuse attestation. |
| RSSI In Range / Out of Range | Fresh advertisement sample compared to the slider threshold. Samples expire after 3 seconds. |
| Ready to Unlock | **Unverified and never asserted**: the full authentication condition and trusted proximity association are not established. |

Advertisement RSSI is an unauthenticated hint matched only to the selected device's current address. Random-address rotation may cause missing samples; matching can be spoofed. This implementation does not resolve IRKs or claim authenticated identity association. The inspected public `BluetoothLEDevice` API has no connected-link RSSI property. RSSI is not a physical-distance or relay-resistance proof.

## Hardware checks

The complete matrix below is **not yet tested**. For each, record Windows/iOS versions, adapter/driver, device model, discovery availability, connection and protected-operation results, first/reconnect latency, RSSI availability and sample gaps, whether lighting the screen was necessary, and recovery actions. Repeat probe attempts and save logs; never treat a name, UUID, bond or connected state as authentication success.

| Scenario | Procedure |
| --- | --- |
| Unlocked, screen on | Pair once; run the probe repeatedly. |
| Locked, screen off | Lock iPhone; repeat without waking it. |
| Screen off 5 minutes | Wait 5 minutes; run probe without waking. |
| Screen off 30 minutes | Wait 30 minutes; run probe without waking. |
| iPhone Bluetooth restart | Disable/enable in Settings; observe disconnect and retry. |
| Out of range and return | Observe disconnect and stale RSSI; return and retry. |
| iPhone reboot | Reboot; record results before and after first native unlock. |
| Apple Watch connected | Repeat screen-off and reconnect tests with Watch connected. |
| Headphones connected | Repeat with headphones actively connected. |
| Windows lock/unlock | Start the probe, lock and unlock normally; inspect retained logs. |
| Windows adapter restart | Disable/enable the adapter; record watcher errors and manual recovery. |

For negative checks, cancel number confirmation, reject iOS notification sharing if offered, select a device without ANCS, disconnect during pairing/discovery/CCCD operations, and remove a system bond in Settings. Each must report failure or unavailable evidence and must never assert Ready to Unlock. Use a dedicated test bond: removing a bond can affect other Bluetooth integrations.

## Feasibility assessment

| Question | Current conclusion |
| --- | --- |
| Eliminate iPhone app / application key exchange? | One user-confirmed no-app LocalSystem diagnostic passed with both devices locked and the desktop app exited. The source replacement is implemented; complete recovery and native Windows unlock acceptance remain pending. |
| Replace Secure Enclave challenge/response with LESC? | Not established. Pairing metadata and requested GATT protection do not expose a complete current-link LESC/key-reuse attestation in this probe. |
| Stable locked / long-standby authentication? | One locked-PC/phone-screen-off diagnostic passed; repeated and long-standby checks remain pending. Apple does not guarantee continuous ANCS publication. |
| RSSI threshold reliability? | Can observe address-associated advertisements, not authenticated connection RSSI or secure distance. Availability and address correlation need hardware evidence. |
| Independent app-free Apple Watch path? | Not established. The ANCS specification describes an iOS notification provider; it does not establish a Watch-hosted equivalent. Watch coexistence is a separate test. |
| Security comparison? | System bonding delegates key custody to the OS and avoids application key provisioning. Service-owned freshness and one-time consumption require acceptance. RSSI/address hints add no cryptographic assurance or relay resistance. |
| Blocking layer? | The no-app locked/screen-off LocalSystem scenario passed; iPhone Bluetooth-off and below-threshold RSSI were rejected. Remaining negative cases, repeatable recovery and long-standby checks are pending. The documented `0x15` restriction did not produce an API rejection in the user's desktop test; actual transmitted payload remains unknown. Apple availability and current-link evidence remain limited. |

The old signing path and iOS app are removed from product source. This diagnostic never calls Credential Provider, password storage or service approval. Its historical results are not acceptance of the current replacement.

## Official references

- [Microsoft advertisement publisher restrictions](https://learn.microsoft.com/en-us/uwp/api/windows.devices.bluetooth.advertisement.bluetoothleadvertisementpublisher?view=winrt-26100): Service Solicitation `0x15` is system-reserved and prohibited.
- [GATT advertising parameters](https://learn.microsoft.com/en-us/uwp/api/windows.devices.bluetooth.genericattributeprofile.gattserviceprovideradvertisingparameters?view=winrt-26100): no Service Solicitation payload property.
- [TI ANCS accessory example](https://github.com/TexasInstruments/ble-sdk-210-extra/blob/master/Projects/ble/ancs/README.md): peripheral/GATT client solicits ANCS; iPhone system Settings can initiate connection without custom iOS code. This is a hardware reference, not Windows runtime evidence.
- [Bluetooth SIG Security Manager specification](https://www.bluetooth.com/wp-content/uploads/Files/Specification/HTML/Core-54/out/en/host/security-manager-specification.html): LESC uses ECDH P-256; its association model determines MITM authentication. Secure Connections alone does not mean authenticated Numeric Comparison.
- [Apple ANCS specification](https://developer.apple.com/library/archive/documentation/CoreBluetooth/Reference/AppleNotificationCenterServiceSpecification/Specification/Specification.html): service publication is not guaranteed; characteristic access requires authorization.
- [Microsoft pairing](https://learn.microsoft.com/en-us/windows/uwp/devices-sensors/pair-devices): custom ceremonies and explicit confirmation.
- [Secure Connections pairing metadata](https://learn.microsoft.com/en-us/uwp/api/windows.devices.bluetooth.bluetoothledevice.wassecureconnectionusedforpairing?view=winrt-26100): reports pairing history, available since Windows 10 1803.
- [GATT desired protection](https://learn.microsoft.com/en-us/uwp/api/windows.devices.bluetooth.genericattributeprofile.gattcharacteristic.protectionlevel?view=winrt-26100) and [protection levels](https://learn.microsoft.com/en-us/uwp/api/windows.devices.bluetooth.genericattributeprofile.gattprotectionlevel?view=winrt-26100).
- [CCCD operation result](https://learn.microsoft.com/en-us/uwp/api/windows.devices.bluetooth.genericattributeprofile.gattcharacteristic.writeclientcharacteristicconfigurationdescriptorwithresultasync?view=winrt-26100).
- [BluetoothLEDevice API](https://learn.microsoft.com/en-us/uwp/api/windows.devices.bluetooth.bluetoothledevice?view=winrt-26100).
