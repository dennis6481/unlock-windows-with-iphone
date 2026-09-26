# GattHost

This component will be a package-identity Windows host for the custom GATT service. The intended APIs are `GattServiceProvider` for foreground publication and `GattServiceProviderConnection`/background Bluetooth activation for the lock-screen lifecycle.

The Microsoft GATT Server documentation requires the `bluetooth` capability and describes the service-provider event model. A normal desktop process must stop advertising when it suspends; therefore the locked-screen behavior must be tested with the packaged/background path, not assumed from a foreground prototype.

The service definition uses four characteristics: iPhone request (`0x01` write), Windows challenge notification, iPhone assertion write and optional result notification. The host will only transport challenge and assertion frames. It will not decide that an iPhone is trusted based on advertisement, device name or RSSI.
