<!-- Created by Rui MA on 03 Oct 2026 -->

# Testing and diagnostics

This guide defines acceptance checks, not recorded product results. The app-free replacement has an x64 Release product build on 11 Oct 2026 (0 errors, 0 warnings; tests disabled). Test compilation/execution, ARM64, installation and the hardware matrix remain pending. Do not mark all acceptance passed or claim a usable product before the matrix completes.

The subsequent Windows-settings-only pairing and inline Status binding changes, including dialog roots, grouped device rows and viewport-constrained shared outer scrolling, have static inspection only; they have not been built or validated on hardware.

Service-to-Diagnostics reporting also has static inspection only. With matching updated service/app binaries, verify failures appear while binding on Status, include the request ID and technical reason, and survive switching pages. Verify unauthorized callers cannot read diagnostics and an unsupported service query reports an error. Lock/unlock must not flash a polling error on Status; a rejection during the same account's lock transition is discarded, while unlocked rejections, account changes and IPC failures still report errors.

BLE timeout details now identify the pending enumeration or GATT operation. This change has static inspection only; verify a timed-out binding reports `BLE deadline exceeded during ...` in Diagnostics without extending the 30-second deadline.

Service association watchers now use the shared paired-only selectors. This change has static inspection only; verify initial enumeration completes and unpairing/removal, ContainerId changes and ambiguous paired associations still invalidate verification.

Detailed service traces have static inspection only. Verify Diagnostics shows progress before completion, paired bond properties, watcher counts/status, GATT results and timings, then success/failure. Polling must not duplicate lines, including when the IPC-bounded trace drops older lines or a new request starts.

Persistent BLE connections, Windows-cached structure, preparation through protected verification and deadline-bounded RSSI waiting have static inspection only. No build, compilation tests, packaging, installation or hardware validation was run for this change. Record connection/session/service changes and distinguish Cached-mode queries from proven object reuse and new protected operations.

## Environment and evidence

The [independent LocalSystem diagnostic](BleSystemPoc.md) has user-reported evidence for no iPhone app, both devices locked, desktop app exited, protected BLE/RSSI success, Bluetooth-off rejection and low-signal rejection. These observations permit implementation; they do not establish final Windows unlock or complete recovery acceptance.

Use the existing supported Windows/iOS versions, native x64/ARM64, a BLE Central-capable adapter/driver and a password-backed MSA physical console. Record:

| Field | Evidence |
| --- | --- |
| Revision/build | Commit, product version, configuration and native architecture. |
| Environment | Windows/iOS build, phone model, adapter/driver and relevant settings. |
| Scenario | Preconditions, exact action, expected and observed behavior. |
| Result | Pass, fail or not tested; static inspection, tests and hardware results remain distinct. |
| Diagnostics | Private original identifiers where needed; redact SIDs, account/device names and IDs in public reports. Never include passwords or nonce bytes. |

## Automated checks

Builds, test compilation/execution, packaging, installation, hardware checks and publishing require explicit authorization for the current task. Static inspection does not substitute for them.

When explicitly authorized:

```powershell
make -C windows test
```

This builds and runs four native programs: saved-credential IPC/state/authorization, protected binding storage, installer decisions and CP policy. Storage tests require an explicitly authorized elevated test environment because their fixtures use SYSTEM/administrator-only writes. Test source covers binding codec corruption/truncation, range checks, previous-format rejection, cancelled atomic commit, caller operation contracts, freshness, deadline and one-time consumption. It has not been compiled or run for this replacement.

The [Release workflow](../.github/workflows/release.yml) builds Windows installers and checks package versions/PE architectures. It has no iOS/IPA job and does not exercise installation, BLE or native unlock.

## First-install setup

- **Save password → bind iPhone**: cancellation/rejection/failure in password setup never starts binding. Complete target identity must match SID, QualifiedUserName and ProviderID.
- Pair through Windows settings and confirm matching numbers on both devices. The app does not display a numeric ceremony or initiate pairing.
- Added/Updated/Removed update the paired-device list without manual Refresh. Returning performs another enumeration; the user must select a device, click **Bind selected device** and confirm. No device auto-registers. Unpaired or removed devices cannot remain selected.
- Existing Windows pairing is reused. Missing/weak/Secure Connections-unconfirmed bonds fail service validation rather than being downgraded.
- Merge paired Classic/BLE entries with the same ContainerId into one name-only row; prefer a nonempty Classic name, then BLE, then Name unavailable. Keep different same-name containers and missing-container endpoints separate. Updates preserve container selection; changed associations invalidate it. Missing/duplicate relationships and wrong endpoint IDs still fail binding.
- During verification, bound-endpoint updates retaining the saved ContainerId and IsPaired=true must not reject binding. Changed/invalid ContainerId, IsPaired=false or invalid pairing values must reject it. This correction has static inspection only.
- Binding and removal confirmations use the visible page's XamlRoot and default to Cancel; dismissing one shows no error or UAC. Successful removal clears the old selection/errors and returns to initial device selection at the top. Binding and removal request confirmation/UAC. A bound phone has removal only; remove it before selecting another on Status. UAC refusal, cancellation, protected-operation or storage failure preserve the original binding. Removal keeps Windows Bluetooth pairing and the saved password.
- Initial binding chooses −100…−20 dBm in 1 dBm steps, default −60. Status dragging changes only pending state; Save requests UAC. Successful save persists across service/PC restart. Refusal/failure restores the saved value and displays its reason.
- UI acceptance remains pending: check Mica/theme colors, sidebar Auto layout without a manual toggle, native sidebar overlay backgrounds in both themes without content showing through, card icons and vertical centering, both threshold sliders retaining their 240 effective-pixel tracks down to the 800 effective-pixel minimum window width, bottom-right binding, removal card confirmation/failure, no header Refresh or page Cancel, password-query Retry in the error InfoBar, and **Just a moment…** throughout lock-screen verification with specific failures retained.
- Check the native upward entrance/fade when switching all four pages, including cached pages and rapid switching. Preserve each page's scroll position, Diagnostics selection and pending edits; respect Windows animation settings. Runtime motion remains unverified.
- Old public-key registration reports **requires rebinding** without decrypting/migrating it. A read, ACL or corruption error is distinct from no binding; an error cannot silently authorize overwrite.
- Verify unlocked target-console setup after service restart, account switch and another administrator's UAC. No stale candidate or alternate account may become the target.

## Minimum end-to-end check

1. Build/install matching Windows components only after authorization. Restart and sign in once with native Windows credentials.
2. Save the target MSA password; complete system pairing and service-verified binding.
3. Confirm the custom iPhone app is absent. Exit the Windows desktop app using tray **Quit**; closing its window only hides it.
4. Lock Windows and keep the phone locked/screen off. Click **Unlock** once; record that Windows actually restores the same account/session.
5. Lock again without clicking: Windows stays locked. Click again for a fresh verification; previous approval cannot be reused.
6. After Windows reboot or sign-out, perform the first native sign-in before testing later unlocks. Repeat with service restart and both architectures when available.

Service **approved** does not replace the actual native Windows session result.

## Authentication and security boundaries

| Scenario | Expected behavior |
| --- | --- |
| Initial sign-in, wrong account, signed-out or remote session | No eligible presence authorization/credential claim. Native sign-in remains available. |
| Ordinary process imitates approve/start/claim/offer | No approval interface; privileged LogonUI operations reject the caller. |
| IPC version 2, removed phone operations, malformed/truncated packets | Explicit rejection; no old transport or signature fallback. |
| Cached structure, historical communication or samples before request start | Structure may be reused; old evidence never authorizes password release. |
| Missing/stale RSSI during verification | Wait within the original deadline; renew expired communication once eligible RSSI arrives. No deadline extension. |
| Fresh RSSI below the saved threshold | Fail immediately without password release or threshold adjustment. |
| Samples before request start, wrong/currently changed address or address type | Reject old correlation; accept only new current-associated samples. Unmatched endpoints fail. |
| GATT list changes before the first complete protected subscribe/read/unsubscribe | Discard provisional structure/evidence and rediscover within the same 30-second deadline. Verify immediate remove/rebind of the same device without Refresh, including a subscription returning ERROR_CANCELLED after a service change. Genuine cancellation/deadline expiry still stops the request; stable protected-operation errors fail as Bluetooth verification errors, not storage errors. |
| GATT list changes after stability, disconnect or system relation invalidation | Invalidate request/grant immediately. |
| Cancel, timeout, suspend/resume, unlock, logoff or console/account change | Invalidate; late callbacks cannot approve or extend the deadline. |
| Pending native operation/cleanup after cancellation | New BLE start returns busy; no extra worker or unbounded retry. |
| Binding/credential changes during a request | Invalidate affected authorization; never adopt another device by name. |
| Claim with communication or RSSI older than 3 seconds | Reject and require new verification. |
| Duplicate claim, CP rebuild, packing failure or native password rejection | Consume once before decrypt; never restore authorization. |

Use an isolated environment for forged caller/context and delay injection. Do not repeatedly submit incorrect real account passwords or install experimental LSA packages on physical machines.

## Pairing and saved-password operations

- Verify all four pages use the outer content scroller with its bar at the right edge: headers/actions scroll with the body, navigation stays fixed and no inner page/device-list/text scroller competes. Resize across compact/expanded navigation and beyond the shared 800 effective-pixel maximum: wide content is centered without right-edge clipping; below the maximum, its left inset stays fixed and its right edge follows the available width. Status/Password headers and body edges align, and right-side actions remain visible. Switching pages restores each position; first visits start at the top. Check the continuous title bar/sidebar/page backdrop without an outer page panel, WinUI TitleBar dragging/double-click/system buttons, theme/DPI and Windows 10/11. Preserve navigation/order, tray behavior and notifications. Status shows binding name and production RSSI settings; Diagnostics contains text history only. Resize motion remains unverified; sidebar Auto switching is unchanged.
- Password queries remain non-sensitive. Save/update/remove retain UAC, verified target identity, PasswordBox/ContentDialog and explicit failure reasons.
- Check repeated clicks, queued UAC, title-bar close, cancel while service verification is pending and app shutdown. Opening Windows settings must not prevent navigating Status or cancelling binding. Old binding must survive pre-commit failure; a completed commit must report its actual state.
- Open binding/removal from setup and Status: the window must appear without `RPC_E_WRONG_THREAD` (`0x8001010E`). Binding controls are created after WinUI application startup on its UI thread.
- Change devices while Windows settings is open; remove/re-pair the target and rotate its address. Check no stale selection or unintended automatic registration.
- Select/copy diagnostic text while snapshots update. Preserve scroll/selection and avoid duplicate event subscriptions when revisiting pages.

## Connection and background recovery

All remaining cases are **not tested** for this product revision. Repeat each without waking the phone or manually reconnecting unless the scenario requires it; record every intervention.

| Scenario | Checks |
| --- | --- |
| Phone leaves and returns | Old grant invalidates; next user click uses fresh communication/RSSI. |
| Native login, repeated lock/unlock and desktop Quit | Service prepares independently, retains connection after each request and remains usable without the desktop. Compare connection, discovery and protected-operation latency. |
| Idle connection and cancellation during background preparation | Idle connection does not return busy; accepted request cancels preparation, waits for pending native operations, then verifies without concurrent BLE work. |
| Cold connection with populated Windows service cache | Wait for Connected/Active before stable structure discovery; log connection readiness separately. Cached structure alone cannot skip live verification. |
| Connected phone with sparse/no advertisements | Only post-request address/type-associated RSSI qualifies; missing samples wait then time out. Never substitute historical RSSI. |
| Bluetooth off/on, repeatedly on both devices | Off rejects; restored pairing/association is re-resolved on a new click. |
| Screen off 5 minutes, 30 minutes and overnight | Record availability, latency, RSSI gaps and whether waking was needed. |
| Suspend/resume, logoff, binding removal or account change | In-flight request invalidates and connection closes; eligible login/resume prepares again without creating authorization. |
| Service restart and PC reboot | No old task/grant survives; binding/threshold persist. |
| Unpair/re-pair, address change, same-name second device | Unique registered system relation remains required; explicit rebinding handles changed endpoints. |
| Watch/headphones coexistence and adapter/driver variants | Record protected operation, signal and recovery results separately. |

Pairing metadata/protected requests do not independently attest current-link LESC/key reuse. RSSI is unauthenticated and is not secure distance or relay resistance. Record these boundaries with results.

## Installer and removal

Exercise clean install, Reinstall, Update, downgrade rejection, restart continuation and Uninstall using the existing [installer guide](../windows/Setup/README.md). Verify self-contained Release imports and clean-machine installation separately on each architecture.

Reject mixed/corrupt payloads, unsafe ACL/reparse paths and incomplete transactions. Hold a product/helper window open during maintenance: it must wait or report the real blockage, not forcibly terminate it. Existing installer schemas/continuation remain unchanged.

After uninstall, verify service/CP/desktop/setup files, password/product binding, Run/shortcut/Settings entries and transaction tasks/staging are removed. Windows system Bluetooth pairing remains. Unknown files or failed deletions block a complete-removal claim.

## Diagnostics

Start with Windows **Diagnostics** and the separate [system BLE diagnostic](BleSystemPoc.md). The read-only component inspector is:

```powershell
& '.\windows\Diagnostics\Get-ComponentsStatus.ps1'
```

It does not start services/tasks, repair installation or mount offline hives. Access/read errors are evidence, not proof of absence.

Compare console/caller eligibility → unique system relation/bond → connection and cached structure → new protected CCCD operation/unsubscribe → current RSSI → one-time offer/claim → native Windows result. Keep approved and actual unlock results separate. Release notes must identify the exact revision and exercised scenarios.
