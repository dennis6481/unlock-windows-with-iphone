<!-- Modified by Rui MA on 26 Sep 2026 -->

# GattHost

The foreground host is built as `unlock_gatt_host`. It creates the custom service and four characteristics, starts an explicitly discoverable/connectable advertisement, accepts the `0x01` request frame, asks `UnlockService` for a challenge, sends it as a notification, forwards the assertion to `UnlockService`, and publishes the service result.

Build and run it from a developer command prompt with the Windows SDK loaded:

```powershell
cmake --build windows/build --target unlock_service_host unlock_gatt_host
windows/build/unlock_service_host.exe
# Keep the service host running in another terminal, then run:
windows/build/unlock_gatt_host.exe
```

The GATT process remains a transport boundary: it does not parse or verify assertion JSON and must never be treated as a Windows unlock authority. The service prototype currently starts without an enrollment key, so a valid iPhone assertion returns `authenticated:false` with `status:"key_not_enrolled"` until the pairing flow is implemented.

The next packaging step is still required. A package identity and the `bluetooth` capability must be added before relying on runtime GATT publication or lock-screen/background behavior. The foreground executable is a compile/API milestone, not the final deployment shape.

The Microsoft GATT Server documentation requires the `bluetooth` capability and describes the service-provider event model. A normal desktop process must stop advertising when it suspends; therefore the locked-screen behavior must be tested with the packaged/background path, not assumed from a foreground prototype.

The service definition uses four characteristics: iPhone request (`0x01` write), Windows challenge notification, iPhone assertion write and optional result notification. The host will only transport challenge and assertion frames. It will not decide that an iPhone is trusted based on advertisement, device name or RSSI.
