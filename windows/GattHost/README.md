# GattHost

The first foreground prototype is now in `main.cpp` and is built as `unlock_gatt_host`. It creates the custom service and four characteristics, accepts the `0x01` request frame, sends a JSON challenge notification, receives an assertion frame, and emits an explicit `authenticated:false` transport result.

Build and run it from a developer command prompt with the Windows SDK loaded:

```powershell
cmake --build windows/build --target unlock_gatt_host
windows/build/unlock_gatt_host.exe
```

This executable is deliberately transport-only. It does not parse or verify assertion JSON, does not enroll a public key, and must never be treated as a Windows unlock authority. The result notification says `authenticated:false` until `UnlockService` owns challenge state and verification.

The next packaging step is still required. A package identity and the `bluetooth` capability must be added before relying on runtime GATT publication or lock-screen/background behavior. The foreground executable is a compile/API milestone, not the final deployment shape.

The Microsoft GATT Server documentation requires the `bluetooth` capability and describes the service-provider event model. A normal desktop process must stop advertising when it suspends; therefore the locked-screen behavior must be tested with the packaged/background path, not assumed from a foreground prototype.

The service definition uses four characteristics: iPhone request (`0x01` write), Windows challenge notification, iPhone assertion write and optional result notification. The host will only transport challenge and assertion frames. It will not decide that an iPhone is trusted based on advertisement, device name or RSSI.
