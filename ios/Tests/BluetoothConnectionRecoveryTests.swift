// Created by Rui MA on 04 Oct 2026

import Foundation
import XCTest
@testable import BluetoothAuthenticationPolicy

final class BluetoothConnectionRecoveryTests: XCTestCase {
    func testNativeStateMustStillBeConnectedBeforeSelectingCandidate() throws {
        var recovery = BluetoothConnectionRecovery()
        let oldID = UUID()
        let newID = UUID()
        let old = try XCTUnwrap(recovery.begin(oldID, source: .restoration))
        let fresh = try XCTUnwrap(recovery.begin(newID, source: .advertisement))
        XCTAssertTrue(recovery.connected(oldID, generation: old.generation))
        XCTAssertTrue(recovery.connected(newID, generation: fresh.generation))
        XCTAssertEqual(recovery.selectConnected(preferred: oldID, available: [newID])?.peripheralID, newID)
    }

    func testRadioResetInvalidatesAttemptsWithoutReusingGeneration() throws {
        var recovery = BluetoothConnectionRecovery()
        let id = UUID()
        let old = try XCTUnwrap(recovery.begin(id, source: .advertisement))
        XCTAssertTrue(recovery.request(id, generation: old.generation))
        XCTAssertTrue(recovery.cancel(id))
        recovery.reset()
        XCTAssertNil(recovery.activeID)
        XCTAssertTrue(recovery.attempts.isEmpty)
        let fresh = try XCTUnwrap(recovery.begin(id, source: .remembered))
        XCTAssertGreaterThan(fresh.generation, old.generation)
        XCTAssertFalse(recovery.connected(id, generation: old.generation))
        XCTAssertNil(recovery.finish(id, generation: old.generation))
        XCTAssertTrue(recovery.request(id, generation: fresh.generation))
    }

    func testRestoredWaiterDoesNotBlockAnAdvertisedConnection() throws {
        var recovery = BluetoothConnectionRecovery()
        var authentication = BluetoothAuthenticationState()
        let oldID = UUID()
        let advertisedID = UUID()
        let restored = try XCTUnwrap(recovery.begin(oldID, source: .restoration))
        authentication.waitForComputer()
        XCTAssertTrue(recovery.request(oldID, generation: restored.generation))
        XCTAssertFalse(authentication.initializationExpired(now: 86_400))
        recovery.beginScanRound()
        let advertised = try XCTUnwrap(recovery.begin(advertisedID, source: .advertisement))
        XCTAssertTrue(recovery.connected(advertisedID, generation: advertised.generation))
        XCTAssertEqual(recovery.selectConnected(preferred: oldID, available: Set(recovery.attempts.keys))?.peripheralID, advertisedID)
        XCTAssertEqual(recovery.attempts[oldID]?.stage, .waiting)
        authentication.connected(now: 86_400)
        XCTAssertEqual(authentication.deadline, 86_410)
        XCTAssertNil(authentication.verifiedComputerID)
    }

    func testDuplicateDiscoveriesDoNotIssueAnotherNativeRequestOrResetBudget() throws {
        var recovery = BluetoothConnectionRecovery()
        let id = UUID()
        let first = try XCTUnwrap(recovery.begin(id, source: .advertisement))
        XCTAssertTrue(recovery.request(id, generation: first.generation))
        XCTAssertFalse(recovery.request(id, generation: first.generation))
        XCTAssertNil(recovery.begin(id, source: .advertisement))
        recovery.beginScanRound()
        XCTAssertNil(recovery.begin(id, source: .remembered))
        let ended = try XCTUnwrap(recovery.finish(id, generation: first.generation))
        let retry = try XCTUnwrap(recovery.retry(ended))
        XCTAssertEqual(retry.remainingRetries, 0)
        XCTAssertFalse(retry.connectionRequested)
        XCTAssertNil(recovery.begin(id, source: .advertisement))
    }

    func testNewConnectedCandidateTakesPrecedenceOverFailedCandidatesRetry() throws {
        var recovery = BluetoothConnectionRecovery()
        let oldID = UUID()
        let newID = UUID()
        let old = try XCTUnwrap(recovery.begin(oldID, source: .advertisement))
        XCTAssertTrue(recovery.connected(oldID, generation: old.generation))
        XCTAssertEqual(recovery.selectConnected(preferred: oldID, available: Set(recovery.attempts.keys))?.peripheralID, oldID)
        let new = try XCTUnwrap(recovery.begin(newID, source: .advertisement))
        XCTAssertTrue(recovery.connected(newID, generation: new.generation))
        XCTAssertNil(recovery.selectConnected(preferred: newID, available: Set(recovery.attempts.keys)))
        XCTAssertTrue(recovery.cancel(oldID))
        XCTAssertNil(recovery.selectConnected(preferred: newID, available: Set(recovery.attempts.keys)))
        let ended = try XCTUnwrap(recovery.finish(oldID, generation: old.generation))
        XCTAssertEqual(recovery.selectConnected(preferred: oldID, available: Set(recovery.attempts.keys))?.peripheralID, newID)
        XCTAssertNotNil(recovery.retry(ended))
        XCTAssertEqual(recovery.activeID, newID)
    }

    func testCancellingRouteRejectsLateConnectAndOldTerminalGeneration() throws {
        var recovery = BluetoothConnectionRecovery()
        let id = UUID()
        let old = try XCTUnwrap(recovery.begin(id, source: .restoration))
        XCTAssertTrue(recovery.cancel(id))
        XCTAssertFalse(recovery.connected(id, generation: old.generation))
        XCTAssertNil(recovery.begin(id, source: .advertisement))
        XCTAssertNotNil(recovery.finish(id, generation: old.generation))
        let fresh = try XCTUnwrap(recovery.begin(id, source: .advertisement))
        XCTAssertGreaterThan(fresh.generation, old.generation)
        XCTAssertNil(recovery.finish(id, generation: old.generation))
        XCTAssertFalse(recovery.connected(id, generation: old.generation))
        XCTAssertTrue(recovery.connected(id, generation: fresh.generation))
    }

    func testExhaustionCannotRearmCachedConnectionThroughScanRestart() throws {
        var recovery = BluetoothConnectionRecovery()
        let id = UUID()
        let first = try XCTUnwrap(recovery.begin(id, source: .remembered))
        let ended = try XCTUnwrap(recovery.finish(id, generation: first.generation))
        let retry = try XCTUnwrap(recovery.retry(ended))
        let exhausted = try XCTUnwrap(recovery.finish(id, generation: retry.generation))
        XCTAssertNil(recovery.retry(exhausted))
        recovery.failed(id)
        recovery.beginScanRound()
        XCTAssertNil(recovery.begin(id, source: .remembered))
        XCTAssertNotNil(recovery.begin(id, source: .advertisement))
    }

    func testExplicitRetryCanEnableCachedRouteButIdentityRejectionStillNeedsNewRound() throws {
        var recovery = BluetoothConnectionRecovery()
        let id = UUID()
        recovery.failed(id)
        recovery.allowRemembered(id)
        let attempt = try XCTUnwrap(recovery.begin(id, source: .remembered))
        recovery.reject(id)
        let ended = try XCTUnwrap(recovery.finish(id, generation: attempt.generation))
        XCTAssertNil(recovery.retry(ended))
        XCTAssertNil(recovery.begin(id, source: .advertisement))
        recovery.beginScanRound()
        XCTAssertNotNil(recovery.begin(id, source: .advertisement))
    }

    func testRetriesBelongToTheDeviceAndResetOnlyAfterReady() throws {
        var recovery = BluetoothConnectionRecovery()
        let id = UUID()
        let first = try XCTUnwrap(recovery.begin(id, source: .advertisement))
        let ended = try XCTUnwrap(recovery.finish(id, generation: first.generation))
        let retry = try XCTUnwrap(recovery.retry(ended))
        XCTAssertTrue(recovery.connected(id, generation: retry.generation))
        XCTAssertEqual(recovery.selectConnected(preferred: id, available: Set(recovery.attempts.keys))?.remainingRetries, 0)
        XCTAssertNotNil(recovery.begin(UUID(), source: .advertisement))
        XCTAssertEqual(recovery.attempts[id]?.remainingRetries, 0)
        recovery.ready(id)
        XCTAssertEqual(recovery.attempts[id]?.remainingRetries, 1)
        recovery.restartInitialization(id)
        XCTAssertEqual(recovery.attempts[id]?.stage, .initializing)
    }

    func testAttemptsAreBoundedAndCancellationOfAnotherRouteDoesNotClearActiveSession() throws {
        var recovery = BluetoothConnectionRecovery()
        let activeID = UUID()
        let active = try XCTUnwrap(recovery.begin(activeID, source: .advertisement))
        XCTAssertTrue(recovery.connected(activeID, generation: active.generation))
        XCTAssertNotNil(recovery.selectConnected(preferred: activeID, available: Set(recovery.attempts.keys)))
        for _ in 1 ..< BluetoothConnectionRecovery.maximumAttempts {
            XCTAssertNotNil(recovery.begin(UUID(), source: .advertisement))
        }
        XCTAssertNil(recovery.begin(UUID(), source: .advertisement))
        let pending = try XCTUnwrap(recovery.attempts.values.first { $0.peripheralID != activeID })
        XCTAssertTrue(recovery.cancel(pending.peripheralID))
        XCTAssertNotNil(recovery.finish(pending.peripheralID, generation: pending.generation))
        XCTAssertEqual(recovery.activeID, activeID)
        XCTAssertNotNil(recovery.begin(UUID(), source: .advertisement))
    }
}
