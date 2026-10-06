// swift-tools-version: 6.2
// Created by Rui MA on 03 Oct 2026

import PackageDescription

let package = Package(
    name: "BluetoothAuthenticationPolicy",
    platforms: [.macOS(.v13), .iOS(.v26)],
    targets: [
        .target(name: "BluetoothAuthenticationPolicy", path: "Core",
                exclude: ["BluetoothAuthenticator.swift", "SecureEnclaveKeyStore.swift",
                          "UnlockError.swift", "UnlockProtocol.swift", "UnlockSetupModel.swift"],
                sources: ["BluetoothAuthenticationState.swift", "BluetoothConnectionRecovery.swift"]),
        .testTarget(name: "BluetoothAuthenticationPolicyTests",
                    dependencies: ["BluetoothAuthenticationPolicy"], path: "Tests")
    ]
)
