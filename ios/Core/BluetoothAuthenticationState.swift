// Created by Rui MA on 03 Oct 2026

import Foundation

struct BluetoothAuthenticationState {
    enum SignalDecision: Equatable { case approve, tooLow, invalid, expired }
    static let responseLifetime: TimeInterval = 3

    static func signalDecision(rssi: Int, threshold: Int, now: TimeInterval,
                               deadline: TimeInterval) -> SignalDecision {
        guard now < deadline else { return .expired }
        guard rssi < 0, rssi >= -127 else { return .invalid }
        return rssi >= threshold ? .approve : .tooLow
    }

    private(set) var remainingConnectionRetries = 1
    mutating func resetConnectionRetries() { remainingConnectionRetries = 1 }
    mutating func takeConnectionRetry() -> Bool {
        guard remainingConnectionRetries > 0 else { return false }
        remainingConnectionRetries -= 1
        return true
    }
}
