// Created by Rui MA on 03 Oct 2026

import Foundation
import XCTest
@testable import BluetoothAuthenticationPolicy

final class BluetoothAuthenticationStateTests: XCTestCase {
    private let computer = UUID(uuidString: "8dca3dcb-5b06-4fa0-92df-64125009d038")!
    private let otherComputer = UUID(uuidString: "5ca9e028-752b-400f-b454-1fe0453a2d64")!

    private func readyState(now: TimeInterval = 0) -> BluetoothAuthenticationState {
        var state = BluetoothAuthenticationState()
        state.connected(now: now)
        state.discoveredServices()
        state.discoveredCharacteristics()
        XCTAssertTrue(state.verifyComputer(computer, expected: computer, enrolling: false))
        XCTAssertTrue(state.subscriptions(challenge: true, result: true, now: now + 1))
        return state
    }

    func testFreshSignalAndDeadlineBoundary() {
        XCTAssertEqual(BluetoothAuthenticationState.signalDecision(rssi: -60, threshold: -60, now: 2, deadline: 3), .approve)
        XCTAssertEqual(BluetoothAuthenticationState.signalDecision(rssi: -61, threshold: -60, now: 2, deadline: 3), .tooLow)
        XCTAssertEqual(BluetoothAuthenticationState.signalDecision(rssi: -40, threshold: -60, now: 3, deadline: 3), .expired)
        for invalid in [127, 0, -128] {
            XCTAssertEqual(BluetoothAuthenticationState.signalDecision(rssi: invalid, threshold: -60, now: 2, deadline: 3), .invalid)
        }
    }

    func testServiceInvalidationRequestsDiscoveryNotReconnect() {
        var state = readyState()
        let generation = state.generation
        XCTAssertTrue(state.invalidateServices(now: 4))
        XCTAssertEqual(state.phase, .services)
        XCTAssertEqual(state.generation, generation + 1)
        XCTAssertNil(state.verifiedComputerID)
        XCTAssertFalse(state.acceptsAuthentication(target: computer, enabled: true, enrolling: false))
        XCTAssertEqual(state.remainingConnectionRetries, 1)
        XCTAssertFalse(state.invalidateServices(now: 5))
        XCTAssertEqual(state.completeDiscoveryStep(now: 6), .rediscover)
        XCTAssertEqual(state.completeDiscoveryStep(now: 7), .proceed)
        XCTAssertEqual(state.deadline, 14)
        state.discoveredServices()
        state.discoveredCharacteristics()
        XCTAssertTrue(state.verifyComputer(computer, expected: computer, enrolling: false))
        XCTAssertFalse(state.subscriptions(challenge: true, result: false, now: 8))
        XCTAssertTrue(state.subscriptions(challenge: true, result: true, now: 9))
    }

    func testInvalidationCoalescesAtEveryDiscoveryStage() {
        for phase in [BluetoothAuthenticationState.Phase.services, .characteristics, .identity] {
            var state = BluetoothAuthenticationState()
            state.connected(now: 0)
            if phase != .services { state.discoveredServices() }
            if phase == .identity { state.discoveredCharacteristics() }
            XCTAssertFalse(state.invalidateServices(now: 1))
            XCTAssertFalse(state.invalidateServices(now: 2))
            XCTAssertEqual(state.completeDiscoveryStep(now: 3), .rediscover)
            XCTAssertEqual(state.phase, .services)
            XCTAssertEqual(state.completeDiscoveryStep(now: 4), .proceed)
        }
    }

    func testRecoveryDeadlineCannotBeExtendedByInvalidation() {
        var state = readyState()
        XCTAssertTrue(state.invalidateServices(now: 10))
        XCTAssertFalse(state.invalidateServices(now: 19))
        XCTAssertEqual(state.deadline, 20)
        XCTAssertEqual(state.completeDiscoveryStep(now: 20), .expired)
    }

    func testConnectedButNotReadyDoesNotResetRetryBudget() {
        var state = BluetoothAuthenticationState()
        XCTAssertTrue(state.takeConnectionRetry())
        state.connecting(now: 0)
        state.connected(now: 1)
        XCTAssertEqual(state.remainingConnectionRetries, 0)
        XCTAssertFalse(state.takeConnectionRetry())
        state.discoveredServices()
        state.discoveredCharacteristics()
        XCTAssertTrue(state.verifyComputer(computer, expected: computer, enrolling: false))
        XCTAssertFalse(state.subscriptions(challenge: false, result: true, now: 2))
        XCTAssertEqual(state.remainingConnectionRetries, 0)
        XCTAssertTrue(state.subscriptions(challenge: true, result: true, now: 3))
        XCTAssertEqual(state.remainingConnectionRetries, 1)
    }

    func testIdentityAndBothSubscriptionsRequired() {
        var state = BluetoothAuthenticationState()
        state.connected(now: 0)
        state.discoveredServices()
        state.discoveredCharacteristics()
        XCTAssertFalse(state.verifyComputer(otherComputer, expected: computer, enrolling: false))
        XCTAssertFalse(state.subscriptions(challenge: true, result: true, now: 1))
        XCTAssertTrue(state.verifyComputer(computer, expected: computer, enrolling: false))
        XCTAssertFalse(state.subscriptions(challenge: true, result: false, now: 2))
        XCTAssertFalse(state.acceptsAuthentication(target: computer, enabled: true, enrolling: false))
        XCTAssertTrue(state.subscriptions(challenge: true, result: true, now: 3))
        XCTAssertTrue(state.acceptsAuthentication(target: computer, enabled: true, enrolling: false))
        XCTAssertFalse(state.acceptsAuthentication(target: otherComputer, enabled: true, enrolling: false))
        XCTAssertFalse(state.acceptsAuthentication(target: computer, enabled: false, enrolling: false))
        XCTAssertFalse(state.acceptsAuthentication(target: computer, enabled: true, enrolling: true))
    }

    func testExpiredSubscriptionSetupCannotBecomeReady() {
        var state = BluetoothAuthenticationState()
        state.connected(now: 0)
        state.discoveredServices()
        state.discoveredCharacteristics()
        XCTAssertTrue(state.verifyComputer(computer, expected: computer, enrolling: false))
        XCTAssertFalse(state.subscriptions(challenge: true, result: true, now: 10))
    }

    func testOldRSSIRemainsInFlightButCannotApproveNewGeneration() {
        var state = readyState()
        let oldRequest = UUID()
        let newRequest = UUID()
        let old = state.beginRSSI(requestID: oldRequest, now: 2)
        XCTAssertNotNil(old)
        XCTAssertTrue(state.invalidateServices(now: 2.1))
        XCTAssertEqual(state.rssiRead, old)
        state.discoveredServices()
        state.discoveredCharacteristics()
        XCTAssertTrue(state.verifyComputer(computer, expected: computer, enrolling: false))
        XCTAssertTrue(state.subscriptions(challenge: true, result: true, now: 2.2))
        XCTAssertNil(state.beginRSSI(requestID: newRequest, now: 2.3))
        XCTAssertNil(state.finishRSSI(now: 2.4, requestID: newRequest))
        let fresh = state.beginRSSI(requestID: newRequest, now: 2.5)
        XCTAssertNotNil(fresh)
        XCTAssertEqual(state.finishRSSI(now: 2.6, requestID: newRequest), fresh)
    }

    func testLateOrWrongRequestRSSICannotBeUsed() {
        var state = readyState()
        let id = UUID()
        XCTAssertNotNil(state.beginRSSI(requestID: id, now: 2))
        XCTAssertNil(state.finishRSSI(now: 5, requestID: id))
        XCTAssertNotNil(state.beginRSSI(requestID: id, now: 6))
        XCTAssertNil(state.finishRSSI(now: 6.1, requestID: UUID()))
        XCTAssertNotNil(state.beginRSSI(requestID: id, now: 7))
        state.disconnected()
        XCTAssertNil(state.rssiRead)
        XCTAssertNil(state.finishRSSI(now: 7.1, requestID: id))
    }

    func testStableIdentityDoesNotDependOnNameOrPeripheralUUID() throws {
        let old = RegisteredComputer(computerID: computer, name: "Windows", peripheralID: UUID())
        let changed = RegisteredComputer(computerID: computer, name: "Renamed", peripheralID: UUID())
        XCTAssertNotEqual(old.peripheralID, changed.peripheralID)
        var state = BluetoothAuthenticationState()
        state.connected(now: 0)
        state.discoveredServices()
        state.discoveredCharacteristics()
        XCTAssertTrue(state.verifyComputer(changed.computerID, expected: old.computerID, enrolling: false))
        XCTAssertEqual(try JSONDecoder().decode(RegisteredComputer.self,
            from: JSONEncoder().encode(changed)), changed)
        XCTAssertEqual(BluetoothAuthenticationState.computerID(from: Data(computer.uuidString.lowercased().utf8)), computer)
        XCTAssertEqual(BluetoothAuthenticationState.computerID(from: Data(computer.uuidString.utf8)), computer)
        for bad in ["", "Windows", "{\(computer)}", "00000000-0000-0000-0000-000000000000"] {
            XCTAssertNil(BluetoothAuthenticationState.computerID(from: Data(bad.utf8)))
        }
    }

    func testEnrollmentResultsAreNotAuthenticationResults() {
        for code in ["enrollment_saved", "enrollment_already_registered"] {
            XCTAssertEqual(BluetoothAuthenticationState.enrollmentOutcome(code: code, detail: nil), .succeeded)
        }
        XCTAssertEqual(BluetoothAuthenticationState.enrollmentOutcome(code: "enrollment_cancelled", detail: nil), .cancelled)
        for code in ["enrollment_rejected", "enrollment_busy", "enrollment_expired", "enrollment_error", "enrollment_removed"] {
            XCTAssertNotEqual(BluetoothAuthenticationState.enrollmentOutcome(code: code, detail: nil), .succeeded)
        }
        XCTAssertNotEqual(BluetoothAuthenticationState.enrollmentOutcome(code: "enrollment_saved",
            detail: "saved_reload_failed"), .succeeded)
        XCTAssertNil(BluetoothAuthenticationState.enrollmentOutcome(code: "unlock_approved", detail: nil))
        XCTAssertNil(BluetoothAuthenticationState.enrollmentOutcome(code: "unknown", detail: "saved_reload_failed"))
    }

    func testAutomaticPreferenceMigratesOnceAndSurvivesConnectionFailures() {
        let name = "BluetoothAuthenticationPolicyTests.\(UUID())"
        let defaults = UserDefaults(suiteName: name)!
        defer { defaults.removePersistentDomain(forName: name) }
        defaults.set(false, forKey: "automaticUnlockEnabled")
        XCTAssertTrue(BluetoothAuthenticationState.automaticPreference(defaults))
        defaults.set(false, forKey: "automaticUnlockEnabled")
        XCTAssertFalse(BluetoothAuthenticationState.automaticPreference(defaults))
        var state = readyState()
        state.invalidateServices(now: 4)
        state.failed()
        state.disconnected()
        XCTAssertFalse(BluetoothAuthenticationState.automaticPreference(defaults))
        defaults.set(true, forKey: "automaticUnlockEnabled")
        XCTAssertTrue(BluetoothAuthenticationState.automaticPreference(defaults))
    }

    func testNewInstallDefaultsToAutomaticResponse() {
        let name = "BluetoothAuthenticationPolicyTests.\(UUID())"
        let defaults = UserDefaults(suiteName: name)!
        defer { defaults.removePersistentDomain(forName: name) }
        XCTAssertTrue(BluetoothAuthenticationState.automaticPreference(defaults))
        XCTAssertEqual(defaults.integer(forKey: "automaticUnlockPreferenceVersion"), 2)
    }

    func testOldOrUnassociatedAuthenticationResultsCannotMatch() {
        let old = UUID()
        let current = UUID()
        XCTAssertFalse(BluetoothAuthenticationState.acceptsResult(requestID: nil, pending: nil, awaiting: nil))
        XCTAssertFalse(BluetoothAuthenticationState.acceptsResult(requestID: old, pending: current, awaiting: nil))
        XCTAssertFalse(BluetoothAuthenticationState.acceptsResult(requestID: old, pending: nil, awaiting: current))
        XCTAssertTrue(BluetoothAuthenticationState.acceptsResult(requestID: current, pending: current, awaiting: nil))
        XCTAssertTrue(BluetoothAuthenticationState.acceptsResult(requestID: current, pending: nil, awaiting: current))
    }

    func testFailedEnrollmentDoesNotOfferReplacementTarget() {
        let old = RegisteredComputer(computerID: computer, name: "Original", peripheralID: UUID())
        let candidate = RegisteredComputer(computerID: otherComputer, name: "Candidate", peripheralID: UUID())
        var snapshot = BluetoothViewState()
        snapshot.target = old
        for outcome in [ComputerEnrollmentState.cancelled, .rejected("rejected"), .failed("reload failed")] {
            XCTAssertNil(snapshot.completeEnrollment(outcome, candidate: candidate))
            XCTAssertEqual(snapshot.target, old)
        }
        XCTAssertEqual(snapshot.completeEnrollment(.succeeded, candidate: candidate), candidate)
        XCTAssertEqual(snapshot.target, old)
    }

    func testOldWriteGenerationCannotAffectRecoveredConnection() {
        var state = readyState()
        let oldGeneration = state.generation
        XCTAssertTrue(state.isCurrentGeneration(oldGeneration))
        state.invalidateServices(now: 2)
        XCTAssertFalse(state.isCurrentGeneration(oldGeneration))
        XCTAssertTrue(state.isCurrentGeneration(state.generation))
    }

    func testSnapshotSeparatesConnectionEnrollmentAndAuthentication() {
        var snapshot = BluetoothViewState()
        snapshot.connection = .ready
        snapshot.enrollment = .rejected("Windows 拒绝登记")
        snapshot.authentication = .rejected("RSSI 不足")
        XCTAssertEqual(snapshot.connection, .ready)
        XCTAssertEqual(snapshot.enrollment.title, "Windows 拒绝登记")
        XCTAssertEqual(snapshot.authentication.title, "RSSI 不足")
        XCTAssertEqual(PhoneAuthenticationState.approved.title, "Windows 已批准，等待电脑完成解锁")
    }

    func testDesktopServiceAbsenceEntersPassiveWaitWithoutUsingRetry() {
        var state = readyState()
        let generation = state.generation
        state.waitForService()
        XCTAssertEqual(state.phase, .waitingService)
        XCTAssertTrue(state.isPassiveWait)
        XCTAssertNil(state.deadline)
        XCTAssertNil(state.verifiedComputerID)
        XCTAssertFalse(state.challengeSubscribed)
        XCTAssertFalse(state.resultSubscribed)
        XCTAssertGreaterThan(state.generation, generation)
        XCTAssertEqual(state.remainingConnectionRetries, 1)
        XCTAssertFalse(state.acceptsAuthentication(target: computer, enabled: true, enrolling: false))
    }

    func testRememberedConnectionCanWaitOvernightButCannotAuthenticate() {
        var state = BluetoothAuthenticationState()
        XCTAssertTrue(state.takeConnectionRetry())
        state.connecting(now: 0, rememberedTarget: true)
        XCTAssertNil(state.deadline)
        XCTAssertTrue(state.isPassiveWait)
        XCTAssertEqual(state.remainingConnectionRetries, 0)
        XCTAssertFalse(state.acceptsAuthentication(target: computer, enabled: true, enrolling: false))
        state.connected(now: 86_400)
        XCTAssertEqual(state.deadline, 86_410)
        XCTAssertFalse(state.isPassiveWait)
        XCTAssertEqual(state.remainingConnectionRetries, 0)
        XCTAssertEqual(state.completeDiscoveryStep(now: 86_410), .expired)
    }

    func testUnknownCandidateStillHasTenSecondConnectionWindow() {
        var state = BluetoothAuthenticationState()
        state.connecting(now: 8)
        XCTAssertEqual(state.deadline, 18)
        XCTAssertFalse(state.isPassiveWait)
        XCTAssertEqual(state.completeDiscoveryStep(now: 18), .expired)
    }

    func testRetryExhaustionWaitsForAnEventInsteadOfRearmingItself() {
        var state = readyState()
        XCTAssertTrue(state.takeConnectionRetry())
        state.failed()
        XCTAssertTrue(state.isPassiveWait)
        XCTAssertNil(state.deadline)
        XCTAssertFalse(state.takeConnectionRetry())
        XCTAssertFalse(state.acceptsAuthentication(target: computer, enabled: true, enrolling: false))
        XCTAssertTrue(state.invalidateServices(now: 100, discoveryPending: false))
        XCTAssertEqual(state.remainingConnectionRetries, 1)
        XCTAssertEqual(state.deadline, 110)
        XCTAssertFalse(state.isPassiveWait)
        XCTAssertFalse(state.invalidateServices(now: 109, discoveryPending: true))
        XCTAssertEqual(state.deadline, 110)
        XCTAssertEqual(state.completeDiscoveryStep(now: 110), .expired)
    }

    func testServiceReturnsAfterLongWaitAndNeedsFreshIdentityAndSubscriptions() {
        var state = readyState()
        state.waitForService()
        XCTAssertTrue(state.invalidateServices(now: 20_000, discoveryPending: false))
        XCTAssertEqual(state.deadline, 20_010)
        XCTAssertFalse(state.subscriptions(challenge: true, result: true, now: 20_001))
        state.discoveredServices()
        state.discoveredCharacteristics()
        XCTAssertFalse(state.verifyComputer(otherComputer, expected: computer, enrolling: false))
        XCTAssertTrue(state.verifyComputer(computer, expected: computer, enrolling: false))
        XCTAssertFalse(state.subscriptions(challenge: true, result: false, now: 20_002))
        XCTAssertTrue(state.subscriptions(challenge: true, result: true, now: 20_003))
    }

    func testLateDiscoveryMustDrainBeforeRecoveryDiscoveryStarts() {
        var state = BluetoothAuthenticationState()
        state.connected(now: 0)
        state.discoveredServices()
        state.failed()
        XCTAssertFalse(state.invalidateServices(now: 30, discoveryPending: true))
        XCTAssertEqual(state.deadline, 40)
        XCTAssertEqual(state.completeDiscoveryStep(now: 31), .rediscover)
        XCTAssertEqual(state.phase, .services)
        XCTAssertEqual(state.completeDiscoveryStep(now: 32), .proceed)
    }

    func testSamePeripheralIsDeduplicatedOnlyWithinItsScanRound() {
        var state = BluetoothAuthenticationState()
        let peripheral = UUID()
        state.beginScanRound()
        let round = state.scanRound
        XCTAssertTrue(state.discoverCandidate(peripheral))
        XCTAssertFalse(state.discoverCandidate(peripheral))
        state.waitForComputer()
        XCTAssertFalse(state.discoverCandidate(peripheral))
        state.beginScanRound()
        XCTAssertEqual(state.scanRound, round + 1)
        XCTAssertTrue(state.discoverCandidate(peripheral))
    }

    func testServiceAdvertisementCanRearmWaitingOnceWithinAScanRound() {
        var state = readyState()
        let peripheral = UUID()
        state.waitForService()
        state.beginScanRound()
        XCTAssertTrue(state.discoverCandidate(peripheral))
        XCTAssertTrue(state.invalidateServices(now: 100, discoveryPending: false))
        XCTAssertEqual(state.deadline, 110)
        state.waitForService()
        XCTAssertFalse(state.discoverCandidate(peripheral))
        XCTAssertNil(state.deadline)
        XCTAssertTrue(state.isPassiveWait)
        XCTAssertTrue(state.invalidateServices(now: 200, discoveryPending: false))
        XCTAssertEqual(state.deadline, 210)
    }

    func testNewPeripheralCanBeDiscoveredWhileOldTargetConnectionIsPending() {
        var state = BluetoothAuthenticationState()
        let oldPeripheral = UUID()
        let newPeripheral = UUID()
        state.beginScanRound()
        XCTAssertTrue(state.discoverCandidate(oldPeripheral))
        state.connecting(now: 0, rememberedTarget: true)
        XCTAssertTrue(state.isPassiveWait)
        XCTAssertTrue(state.discoverCandidate(newPeripheral))
        XCTAssertFalse(state.discoverCandidate(newPeripheral))
        state.disconnected()
        state.connecting(now: 20)
        state.connected(now: 21)
        state.discoveredServices()
        state.discoveredCharacteristics()
        XCTAssertFalse(state.verifyComputer(otherComputer, expected: computer, enrolling: false))
        XCTAssertTrue(state.verifyComputer(computer, expected: computer, enrolling: false))
    }

    func testCandidateHistoryIsBoundedAndClearedAtANewScanRound() {
        var state = BluetoothAuthenticationState()
        state.beginScanRound()
        for _ in 0 ..< 64 { XCTAssertTrue(state.discoverCandidate(UUID())) }
        let next = UUID()
        XCTAssertTrue(state.discoverCandidate(next))
        XCTAssertEqual(state.candidateHistoryCount, 64)
        XCTAssertFalse(state.discoverCandidate(next))
        state.beginScanRound()
        XCTAssertEqual(state.candidateHistoryCount, 0)
        XCTAssertTrue(state.discoverCandidate(next))
    }

    func testWaitingInvalidatesOldRSSIAndWriteGeneration() {
        var state = readyState()
        let request = UUID()
        let oldGeneration = state.generation
        let oldRead = state.beginRSSI(requestID: request, now: 2)
        state.waitForService()
        XCTAssertEqual(state.rssiRead, oldRead)
        XCTAssertFalse(state.isCurrentGeneration(oldGeneration))
        XCTAssertNil(state.finishRSSI(now: 2.1, requestID: request))
        XCTAssertNil(state.beginRSSI(requestID: UUID(), now: 2.2))
        state.waitForComputer()
        XCTAssertFalse(state.acceptsAuthentication(target: computer, enabled: true, enrolling: false))
    }

    func testWaitingDoesNotChangeAutomaticResponsePreference() {
        let name = "BluetoothWaitingTests.\(UUID())"
        let defaults = UserDefaults(suiteName: name)!
        defer { defaults.removePersistentDomain(forName: name) }
        XCTAssertTrue(BluetoothAuthenticationState.automaticPreference(defaults))
        defaults.set(false, forKey: "automaticUnlockEnabled")
        var state = readyState()
        state.waitForService()
        state.waitForComputer()
        state.connecting(now: 100, rememberedTarget: true)
        XCTAssertFalse(BluetoothAuthenticationState.automaticPreference(defaults))
        XCTAssertFalse(state.acceptsAuthentication(target: computer, enabled: false, enrolling: false))
    }

    func testWaitingServiceTitleDoesNotClaimUnlockChannelReady() {
        var snapshot = BluetoothViewState()
        snapshot.connection = .waitingService
        XCTAssertEqual(snapshot.connection.title, "蓝牙已连接，等待解锁服务")
        XCTAssertNil(snapshot.connection.failure)
        snapshot.connection = .failed("阶段：subscriptions；仍在等待电脑恢复")
        XCTAssertEqual(snapshot.connection.title, "通道初始化异常")
        XCTAssertNotNil(snapshot.connection.failure)
    }
}
