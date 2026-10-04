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
        XCTAssertTrue(state.verifyComputer(computer, expected: computer, enrolling: false, now: now))
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
        XCTAssertFalse(state.invalidateServices(now: 5))
        XCTAssertEqual(state.completeDiscoveryStep(now: 6), .rediscover)
        XCTAssertEqual(state.completeDiscoveryStep(now: 7), .proceed)
        XCTAssertEqual(state.deadline, 14)
        state.discoveredServices()
        state.discoveredCharacteristics()
        XCTAssertTrue(state.verifyComputer(computer, expected: computer, enrolling: false, now: 7))
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

    func testInitializationDeadlineIsNotExtendedByDiscoveryOrOneSubscription() {
        var state = BluetoothAuthenticationState()
        state.connected(now: 1)
        state.discoveredServices()
        state.discoveredCharacteristics()
        XCTAssertTrue(state.verifyComputer(computer, expected: computer, enrolling: false, now: 2))
        XCTAssertFalse(state.subscriptions(challenge: false, result: true, now: 3))
        XCTAssertEqual(state.deadline, 11)
        XCTAssertTrue(state.initializationExpired(now: 11))
        XCTAssertFalse(state.subscriptions(challenge: true, result: true, now: 11))
    }

    func testIdentityAndBothSubscriptionsRequired() {
        var state = BluetoothAuthenticationState()
        state.connected(now: 0)
        state.discoveredServices()
        state.discoveredCharacteristics()
        XCTAssertFalse(state.verifyComputer(otherComputer, expected: computer, enrolling: false, now: 1))
        XCTAssertFalse(state.subscriptions(challenge: true, result: true, now: 1))
        XCTAssertTrue(state.verifyComputer(computer, expected: computer, enrolling: false, now: 1))
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
        XCTAssertTrue(state.verifyComputer(computer, expected: computer, enrolling: false, now: 1))
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
        XCTAssertTrue(state.verifyComputer(computer, expected: computer, enrolling: false, now: 2.2))
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
        XCTAssertTrue(state.verifyComputer(changed.computerID, expected: old.computerID, enrolling: false, now: 1))
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

    func testServiceAbsenceClearsQualificationAndRequiresAdvertisement() {
        var state = readyState()
        let generation = state.generation
        state.serviceMissing()
        XCTAssertEqual(state.phase, .waitingComputer)
        XCTAssertTrue(state.requiresAdvertisement)
        XCTAssertNil(state.deadline)
        XCTAssertNil(state.verifiedComputerID)
        XCTAssertFalse(state.challengeSubscribed)
        XCTAssertFalse(state.resultSubscribed)
        XCTAssertGreaterThan(state.generation, generation)
        XCTAssertFalse(state.acceptsAuthentication(target: computer, enabled: true, enrolling: false))
    }

    func testWaitingOvernightDoesNotStartTheInitializationDeadline() {
        var state = BluetoothAuthenticationState()
        state.waitForComputer()
        XCTAssertNil(state.deadline)
        XCTAssertFalse(state.initializationExpired(now: 86_400))
        XCTAssertFalse(state.acceptsAuthentication(target: computer, enabled: true, enrolling: false))
        state.connected(now: 86_400)
        XCTAssertEqual(state.deadline, 86_410)
        XCTAssertFalse(state.initializationExpired(now: 86_409.999))
        XCTAssertTrue(state.initializationExpired(now: 86_410))
        XCTAssertEqual(state.completeDiscoveryStep(now: 86_410), .expired)
    }

    func testSuspendedInitializationExpiresBeforeLateIdentityOrPreparation() {
        var state = BluetoothAuthenticationState()
        state.connected(now: 0)
        let generation = state.generation
        state.discoveredServices()
        state.discoveredCharacteristics()
        XCTAssertTrue(state.initializationExpired(now: 61))
        XCTAssertFalse(state.verifyComputer(computer, expected: computer, enrolling: false, now: 61))
        XCTAssertFalse(state.cacheReadyProbe(UUID(), generation: generation, now: 61))
        XCTAssertFalse(state.subscriptions(challenge: true, result: true, now: 61))
        XCTAssertFalse(state.acceptsAuthentication(target: computer, enabled: true, enrolling: false))
    }

    func testPreparationCannotFinishSuspendedSubscriptionInitialization() {
        var state = BluetoothAuthenticationState()
        let request = UUID()
        state.connected(now: 0)
        state.discoveredServices()
        state.discoveredCharacteristics()
        XCTAssertTrue(state.verifyComputer(computer, expected: computer, enrolling: false, now: 1))
        XCTAssertTrue(state.cacheReadyProbe(request, generation: state.generation, now: 2))
        XCTAssertFalse(state.subscriptions(challenge: true, result: false, now: 3))
        XCTAssertTrue(state.initializationExpired(now: 61))
        XCTAssertFalse(state.subscriptions(challenge: true, result: true, now: 61))
        XCTAssertNil(state.beginReadyAcknowledgment(now: 61))
        XCTAssertFalse(state.acceptsPreparedChallenge(request, now: 61))
    }

    func testFailedInitializationClearsDeadlineAndAuthorization() {
        var state = readyState()
        state.failed()
        XCTAssertNil(state.deadline)
        XCTAssertFalse(state.acceptsAuthentication(target: computer, enabled: true, enrolling: false))
        state.connected(now: 100)
        XCTAssertEqual(state.deadline, 110)
        XCTAssertFalse(state.invalidateServices(now: 109, discoveryPending: true))
        XCTAssertEqual(state.deadline, 110)
        XCTAssertFalse(state.initializationExpired(now: 109))
        XCTAssertTrue(state.initializationExpired(now: 110))
        XCTAssertEqual(state.completeDiscoveryStep(now: 110), .expired)
    }

    func testServiceReturnsAfterLongWaitAndNeedsFreshIdentityAndSubscriptions() {
        var state = readyState()
        state.serviceMissing()
        state.disconnected()
        state.connected(now: 20_000)
        XCTAssertEqual(state.deadline, 20_010)
        XCTAssertFalse(state.subscriptions(challenge: true, result: true, now: 20_001))
        state.discoveredServices()
        state.discoveredCharacteristics()
        XCTAssertFalse(state.verifyComputer(otherComputer, expected: computer, enrolling: false, now: 20_001))
        XCTAssertTrue(state.verifyComputer(computer, expected: computer, enrolling: false, now: 20_001))
        XCTAssertFalse(state.subscriptions(challenge: true, result: false, now: 20_002))
        XCTAssertTrue(state.subscriptions(challenge: true, result: true, now: 20_003))
    }

    func testWaitingInvalidatesOldRSSIAndWriteGeneration() {
        var state = readyState()
        let request = UUID()
        let oldGeneration = state.generation
        let oldRead = state.beginRSSI(requestID: request, now: 2)
        state.serviceMissing()
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
        state.serviceMissing()
        state.waitForComputer()
        XCTAssertFalse(BluetoothAuthenticationState.automaticPreference(defaults))
        XCTAssertFalse(state.acceptsAuthentication(target: computer, enabled: false, enrolling: false))
    }

    func testWaitingComputerTitleDoesNotClaimUnlockChannelReady() {
        var snapshot = BluetoothViewState()
        snapshot.connection = .waitingComputer
        XCTAssertEqual(snapshot.connection.title, "等待目标电脑广播")
        XCTAssertNil(snapshot.connection.failure)
        snapshot.connection = .failed("阶段：subscriptions；仍在等待电脑恢复")
        XCTAssertEqual(snapshot.connection.title, "通道初始化异常")
        XCTAssertNotNil(snapshot.connection.failure)
    }

    func testMissingServiceRestrictionSurvivesConnectionRelease() {
        var state = readyState()
        state.serviceMissing()
        state.failed()
        state.disconnected()
        state.waitForComputer()
        XCTAssertTrue(state.requiresAdvertisement)
        XCTAssertNil(state.deadline)
        state.connected(now: 101)
        state.discoveredServices()
        state.discoveredCharacteristics()
        XCTAssertTrue(state.verifyComputer(computer, expected: computer, enrolling: false, now: 101))
        XCTAssertFalse(state.subscriptions(challenge: true, result: false, now: 102))
        XCTAssertTrue(state.requiresAdvertisement)
        XCTAssertTrue(state.subscriptions(challenge: true, result: true, now: 103))
        XCTAssertFalse(state.requiresAdvertisement)
    }

    func testEarlyReadyProbeWaitsForIdentityAndBothSubscriptions() {
        var state = BluetoothAuthenticationState()
        let request = UUID()
        state.connected(now: 0)
        XCTAssertTrue(state.cacheReadyProbe(request, generation: state.generation, now: 1))
        XCTAssertNil(state.beginReadyAcknowledgment(now: 1))
        XCTAssertFalse(state.acceptsPreparedChallenge(request, now: 1))
        state.discoveredServices()
        state.discoveredCharacteristics()
        XCTAssertTrue(state.verifyComputer(computer, expected: computer, enrolling: false, now: 1))
        XCTAssertFalse(state.subscriptions(challenge: true, result: false, now: 2))
        XCTAssertNil(state.beginReadyAcknowledgment(now: 2))
        XCTAssertTrue(state.subscriptions(challenge: true, result: true, now: 3))
        XCTAssertEqual(state.beginReadyAcknowledgment(now: 3), request)
        XCTAssertTrue(state.acceptsPreparedChallenge(request, now: 3))
        XCTAssertFalse(state.acceptsPreparedChallenge(UUID(), now: 3))
    }

    func testDuplicateProbeCannotExtendDeadlineOrQueueConcurrentWrites() {
        var state = readyState()
        let request = UUID()
        XCTAssertTrue(state.cacheReadyProbe(request, generation: state.generation, now: 1))
        XCTAssertEqual(state.beginReadyAcknowledgment(now: 2), request)
        XCTAssertNil(state.beginReadyAcknowledgment(now: 2.1))
        XCTAssertFalse(state.cacheReadyProbe(UUID(), generation: state.generation, now: 2.1))
        XCTAssertEqual(state.readyProbe?.requestID, request)
        XCTAssertTrue(state.cacheReadyProbe(request, generation: state.generation, now: 29))
        XCTAssertEqual(state.readyProbe?.deadline, 31)
        state.finishReadyAcknowledgment(request, generation: state.generation)
        XCTAssertEqual(state.beginReadyAcknowledgment(now: 30), request)
        XCTAssertFalse(state.cacheReadyProbe(request, generation: state.generation, now: 31))
        XCTAssertNil(state.beginReadyAcknowledgment(now: 31))
        XCTAssertFalse(state.acceptsPreparedChallenge(request, now: 31))
    }

    func testServiceChangeAndCancellationDiscardPreparedRequest() {
        var state = readyState()
        let request = UUID()
        let generation = state.generation
        XCTAssertTrue(state.cacheReadyProbe(request, generation: generation, now: 1))
        XCTAssertEqual(state.beginReadyAcknowledgment(now: 2), request)
        XCTAssertTrue(state.invalidateServices(now: 3, discoveryPending: false))
        XCTAssertNil(state.readyProbe)
        XCTAssertFalse(state.cacheReadyProbe(request, generation: generation, now: 4))
        state.finishReadyAcknowledgment(request, generation: generation)
        XCTAssertFalse(state.acceptsPreparedChallenge(request, now: 4))
        state.connected(now: 5)
        XCTAssertTrue(state.cacheReadyProbe(UUID(), generation: state.generation, now: 6))
        state.disconnected()
        XCTAssertNil(state.readyProbe)
        XCTAssertNil(state.beginReadyAcknowledgment(now: 7))
    }

    func testOldReceiptCannotFinishNewPreparationWrite() {
        var state = readyState()
        let oldRequest = UUID()
        let newRequest = UUID()
        XCTAssertTrue(state.cacheReadyProbe(oldRequest, generation: state.generation, now: 1))
        XCTAssertEqual(state.beginReadyAcknowledgment(now: 1), oldRequest)
        state.clearReadyProbe()
        XCTAssertTrue(state.cacheReadyProbe(newRequest, generation: state.generation, now: 2))
        XCTAssertEqual(state.beginReadyAcknowledgment(now: 2), newRequest)
        state.finishReadyAcknowledgment(oldRequest, generation: state.generation)
        XCTAssertNil(state.beginReadyAcknowledgment(now: 2.1))
        XCTAssertFalse(state.acceptsPreparedChallenge(oldRequest, now: 2.1))
        XCTAssertTrue(state.acceptsPreparedChallenge(newRequest, now: 2.1))
        state.clearReadyProbe()
        XCTAssertFalse(state.acceptsPreparedChallenge(newRequest, now: 2.2))
    }
}
