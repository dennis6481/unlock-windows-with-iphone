// Created by Rui MA on 03 Oct 2026

import XCTest
@testable import BluetoothAuthenticationPolicy

final class BluetoothAuthenticationStateTests: XCTestCase {
    func testFreshSignalAndDeadlineBoundary() {
        XCTAssertEqual(BluetoothAuthenticationState.signalDecision(rssi: -60, threshold: -60, now: 2, deadline: 3), .approve)
        XCTAssertEqual(BluetoothAuthenticationState.signalDecision(rssi: -61, threshold: -60, now: 2, deadline: 3), .tooLow)
        XCTAssertEqual(BluetoothAuthenticationState.signalDecision(rssi: -40, threshold: -60, now: 3, deadline: 3), .expired)
        for invalid in [127, 0, -128] {
            XCTAssertEqual(BluetoothAuthenticationState.signalDecision(rssi: invalid, threshold: -60, now: 2, deadline: 3), .invalid)
        }
    }

    func testConnectionFailureRetryIsBounded() {
        var state = BluetoothAuthenticationState()
        XCTAssertTrue(state.takeConnectionRetry())
        XCTAssertFalse(state.takeConnectionRetry())
        state.resetConnectionRetries()
        XCTAssertTrue(state.takeConnectionRetry())
        XCTAssertFalse(state.takeConnectionRetry())
    }
}
