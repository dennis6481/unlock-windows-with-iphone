// Created by Rui MA on 07 Oct 2026

import Foundation
import Testing
@testable import ios

private func expectResult(
    _ condition: Bool,
    sourceLocation: SourceLocation = #_sourceLocation
) {
    #expect(condition, sourceLocation: sourceLocation)
}

private func requireResult<Value>(
    _ value: Value?,
    sourceLocation: SourceLocation = #_sourceLocation
) throws -> Value {
    try #require(value, sourceLocation: sourceLocation)
}

@MainActor
struct BluetoothConnectionRecoveryTests {
    @Test func nativeStateMustStillBeConnectedBeforeSelectingCandidate() throws {
        var recovery = BluetoothConnectionRecovery()
        let oldID = UUID()
        let newID = UUID()
        let old = try requireResult(recovery.begin(oldID, source: .restoration))
        let fresh = try requireResult(recovery.begin(newID, source: .advertisement))
        expectResult(recovery.connected(oldID, generation: old.generation))
        expectResult(recovery.connected(newID, generation: fresh.generation))
        expectResult((recovery.selectConnected(preferred: oldID, available: [newID])?.peripheralID) == (newID))
    }

    @Test func radioResetInvalidatesAttemptsWithoutReusingGeneration() throws {
        var recovery = BluetoothConnectionRecovery()
        let id = UUID()
        let old = try requireResult(recovery.begin(id, source: .advertisement))
        expectResult(recovery.request(id, generation: old.generation))
        expectResult(recovery.cancel(id))
        recovery.reset()
        expectResult((recovery.activeID) == nil)
        expectResult(recovery.attempts.isEmpty)
        let fresh = try requireResult(recovery.begin(id, source: .remembered))
        expectResult((fresh.generation) > (old.generation))
        expectResult(!(recovery.connected(id, generation: old.generation)))
        expectResult((recovery.finish(id, generation: old.generation)) == nil)
        expectResult(recovery.request(id, generation: fresh.generation))
    }

    @Test func restoredWaiterDoesNotBlockAnAdvertisedConnection() throws {
        var recovery = BluetoothConnectionRecovery()
        var authentication = BluetoothAuthenticationState()
        let oldID = UUID()
        let advertisedID = UUID()
        let restored = try requireResult(recovery.begin(oldID, source: .restoration))
        authentication.waitForComputer()
        expectResult(recovery.request(oldID, generation: restored.generation))
        expectResult(!(authentication.initializationExpired(now: 86_400)))
        recovery.beginScanRound()
        let advertised = try requireResult(recovery.begin(advertisedID, source: .advertisement))
        expectResult(recovery.connected(advertisedID, generation: advertised.generation))
        expectResult((recovery.selectConnected(preferred: oldID, available: Set(recovery.attempts.keys))?.peripheralID) == (advertisedID))
        expectResult((recovery.attempts[oldID]?.stage) == (.waiting))
        authentication.connected(now: 86_400)
        expectResult((authentication.deadline) == (86_410))
        expectResult((authentication.verifiedComputerID) == nil)
    }

    @Test func duplicateDiscoveriesDoNotIssueAnotherNativeRequestOrResetBudget() throws {
        var recovery = BluetoothConnectionRecovery()
        let id = UUID()
        let first = try requireResult(recovery.begin(id, source: .advertisement))
        expectResult(recovery.request(id, generation: first.generation))
        expectResult(!(recovery.request(id, generation: first.generation)))
        expectResult((recovery.begin(id, source: .advertisement)) == nil)
        recovery.beginScanRound()
        expectResult((recovery.begin(id, source: .remembered)) == nil)
        let ended = try requireResult(recovery.finish(id, generation: first.generation))
        let retry = try requireResult(recovery.retry(ended))
        expectResult((retry.remainingRetries) == (0))
        expectResult(!(retry.connectionRequested))
        expectResult((recovery.begin(id, source: .advertisement)) == nil)
    }

    @Test func newConnectedCandidateTakesPrecedenceOverFailedCandidatesRetry() throws {
        var recovery = BluetoothConnectionRecovery()
        let oldID = UUID()
        let newID = UUID()
        let old = try requireResult(recovery.begin(oldID, source: .advertisement))
        expectResult(recovery.connected(oldID, generation: old.generation))
        expectResult((recovery.selectConnected(preferred: oldID, available: Set(recovery.attempts.keys))?.peripheralID) == (oldID))
        let new = try requireResult(recovery.begin(newID, source: .advertisement))
        expectResult(recovery.connected(newID, generation: new.generation))
        expectResult((recovery.selectConnected(preferred: newID, available: Set(recovery.attempts.keys))) == nil)
        expectResult(recovery.cancel(oldID))
        expectResult((recovery.selectConnected(preferred: newID, available: Set(recovery.attempts.keys))) == nil)
        let ended = try requireResult(recovery.finish(oldID, generation: old.generation))
        expectResult((recovery.selectConnected(preferred: oldID, available: Set(recovery.attempts.keys))?.peripheralID) == (newID))
        expectResult((recovery.retry(ended)) != nil)
        expectResult((recovery.activeID) == (newID))
    }

    @Test func cancellingRouteRejectsLateConnectAndOldTerminalGeneration() throws {
        var recovery = BluetoothConnectionRecovery()
        let id = UUID()
        let old = try requireResult(recovery.begin(id, source: .restoration))
        expectResult(recovery.cancel(id))
        expectResult(!(recovery.connected(id, generation: old.generation)))
        expectResult((recovery.begin(id, source: .advertisement)) == nil)
        expectResult((recovery.finish(id, generation: old.generation)) != nil)
        let fresh = try requireResult(recovery.begin(id, source: .advertisement))
        expectResult((fresh.generation) > (old.generation))
        expectResult((recovery.finish(id, generation: old.generation)) == nil)
        expectResult(!(recovery.connected(id, generation: old.generation)))
        expectResult(recovery.connected(id, generation: fresh.generation))
    }

    @Test func exhaustionCannotRearmCachedConnectionThroughScanRestart() throws {
        var recovery = BluetoothConnectionRecovery()
        let id = UUID()
        let first = try requireResult(recovery.begin(id, source: .remembered))
        let ended = try requireResult(recovery.finish(id, generation: first.generation))
        let retry = try requireResult(recovery.retry(ended))
        let exhausted = try requireResult(recovery.finish(id, generation: retry.generation))
        expectResult((recovery.retry(exhausted)) == nil)
        recovery.failed(id)
        recovery.beginScanRound()
        expectResult((recovery.begin(id, source: .remembered)) == nil)
        expectResult((recovery.begin(id, source: .advertisement)) != nil)
    }

    @Test func explicitRetryCanEnableCachedRouteButIdentityRejectionStillNeedsNewRound() throws {
        var recovery = BluetoothConnectionRecovery()
        let id = UUID()
        recovery.failed(id)
        recovery.allowRemembered(id)
        let attempt = try requireResult(recovery.begin(id, source: .remembered))
        recovery.reject(id)
        let ended = try requireResult(recovery.finish(id, generation: attempt.generation))
        expectResult((recovery.retry(ended)) == nil)
        expectResult((recovery.begin(id, source: .advertisement)) == nil)
        recovery.beginScanRound()
        expectResult((recovery.begin(id, source: .advertisement)) != nil)
    }

    @Test func retriesBelongToTheDeviceAndResetOnlyAfterReady() throws {
        var recovery = BluetoothConnectionRecovery()
        let id = UUID()
        let first = try requireResult(recovery.begin(id, source: .advertisement))
        let ended = try requireResult(recovery.finish(id, generation: first.generation))
        let retry = try requireResult(recovery.retry(ended))
        expectResult(recovery.connected(id, generation: retry.generation))
        expectResult((recovery.selectConnected(preferred: id, available: Set(recovery.attempts.keys))?.remainingRetries) == (0))
        expectResult((recovery.begin(UUID(), source: .advertisement)) != nil)
        expectResult((recovery.attempts[id]?.remainingRetries) == (0))
        recovery.ready(id)
        expectResult((recovery.attempts[id]?.remainingRetries) == (1))
        recovery.restartInitialization(id)
        expectResult((recovery.attempts[id]?.stage) == (.initializing))
    }

    @Test func attemptsAreBoundedAndCancellationOfAnotherRouteDoesNotClearActiveSession() throws {
        var recovery = BluetoothConnectionRecovery()
        let activeID = UUID()
        let active = try requireResult(recovery.begin(activeID, source: .advertisement))
        expectResult(recovery.connected(activeID, generation: active.generation))
        expectResult((recovery.selectConnected(preferred: activeID, available: Set(recovery.attempts.keys))) != nil)
        for _ in 1 ..< BluetoothConnectionRecovery.maximumAttempts {
            expectResult((recovery.begin(UUID(), source: .advertisement)) != nil)
        }
        expectResult((recovery.begin(UUID(), source: .advertisement)) == nil)
        let pending = try requireResult(recovery.attempts.values.first { $0.peripheralID != activeID })
        expectResult(recovery.cancel(pending.peripheralID))
        expectResult((recovery.finish(pending.peripheralID, generation: pending.generation)) != nil)
        expectResult((recovery.activeID) == (activeID))
        expectResult((recovery.begin(UUID(), source: .advertisement)) != nil)
    }
}

@MainActor
struct BluetoothAuthenticationStateTests {
    private let computer = UUID(uuidString: "8dca3dcb-5b06-4fa0-92df-64125009d038")!
    private let otherComputer = UUID(uuidString: "5ca9e028-752b-400f-b454-1fe0453a2d64")!

    private func readyState(now: TimeInterval = 0) -> BluetoothAuthenticationState {
        var state = BluetoothAuthenticationState()
        state.connected(now: now)
        state.discoveredServices()
        state.discoveredCharacteristics()
        expectResult(state.verifyComputer(computer, expected: computer, enrolling: false, now: now))
        expectResult(state.subscriptions(challenge: true, result: true, now: now + 1))
        return state
    }

    @Test func freshSignalAndDeadlineBoundary() {
        expectResult((BluetoothAuthenticationState.signalDecision(rssi: -60, threshold: -60, now: 2, deadline: 3)) == (.approve))
        expectResult((BluetoothAuthenticationState.signalDecision(rssi: -61, threshold: -60, now: 2, deadline: 3)) == (.tooLow))
        expectResult((BluetoothAuthenticationState.signalDecision(rssi: -40, threshold: -60, now: 3, deadline: 3)) == (.expired))
        for invalid in [127, 0, -128] {
            expectResult((BluetoothAuthenticationState.signalDecision(rssi: invalid, threshold: -60, now: 2, deadline: 3)) == (.invalid))
        }
    }

    @Test func serviceInvalidationRequestsDiscoveryNotReconnect() {
        var state = readyState()
        let generation = state.generation
        expectResult(state.invalidateServices(now: 4))
        expectResult((state.phase) == (.services))
        expectResult((state.generation) == (generation + 1))
        expectResult((state.verifiedComputerID) == nil)
        expectResult(!(state.acceptsAuthentication(target: computer, enrolling: false)))
        expectResult(!(state.invalidateServices(now: 5)))
        expectResult((state.completeDiscoveryStep(now: 6)) == (.rediscover))
        expectResult((state.completeDiscoveryStep(now: 7)) == (.proceed))
        expectResult((state.deadline) == (14))
        state.discoveredServices()
        state.discoveredCharacteristics()
        expectResult(state.verifyComputer(computer, expected: computer, enrolling: false, now: 7))
        expectResult(!(state.subscriptions(challenge: true, result: false, now: 8)))
        expectResult(state.subscriptions(challenge: true, result: true, now: 9))
    }

    @Test func invalidationCoalescesAtEveryDiscoveryStage() {
        for phase in [BluetoothAuthenticationState.Phase.services, .characteristics, .identity] {
            var state = BluetoothAuthenticationState()
            state.connected(now: 0)
            if phase != .services { state.discoveredServices() }
            if phase == .identity { state.discoveredCharacteristics() }
            expectResult(!(state.invalidateServices(now: 1)))
            expectResult(!(state.invalidateServices(now: 2)))
            expectResult((state.completeDiscoveryStep(now: 3)) == (.rediscover))
            expectResult((state.phase) == (.services))
            expectResult((state.completeDiscoveryStep(now: 4)) == (.proceed))
        }
    }

    @Test func recoveryDeadlineCannotBeExtendedByInvalidation() {
        var state = readyState()
        expectResult(state.invalidateServices(now: 10))
        expectResult(!(state.invalidateServices(now: 19)))
        expectResult((state.deadline) == (20))
        expectResult((state.completeDiscoveryStep(now: 20)) == (.expired))
    }

    @Test func initializationDeadlineIsNotExtendedByDiscoveryOrOneSubscription() {
        var state = BluetoothAuthenticationState()
        state.connected(now: 1)
        state.discoveredServices()
        state.discoveredCharacteristics()
        expectResult(state.verifyComputer(computer, expected: computer, enrolling: false, now: 2))
        expectResult(!(state.subscriptions(challenge: false, result: true, now: 3)))
        expectResult((state.deadline) == (11))
        expectResult(state.initializationExpired(now: 11))
        expectResult(!(state.subscriptions(challenge: true, result: true, now: 11)))
    }

    @Test func identityAndBothSubscriptionsRequired() {
        var state = BluetoothAuthenticationState()
        state.connected(now: 0)
        state.discoveredServices()
        state.discoveredCharacteristics()
        expectResult(!(state.verifyComputer(otherComputer, expected: computer, enrolling: false, now: 1)))
        expectResult(!(state.subscriptions(challenge: true, result: true, now: 1)))
        expectResult(state.verifyComputer(computer, expected: computer, enrolling: false, now: 1))
        expectResult(!(state.subscriptions(challenge: true, result: false, now: 2)))
        expectResult(!(state.acceptsAuthentication(target: computer, enrolling: false)))
        expectResult(state.subscriptions(challenge: true, result: true, now: 3))
        expectResult(state.acceptsAuthentication(target: computer, enrolling: false))
        expectResult(!(state.acceptsAuthentication(target: otherComputer, enrolling: false)))
        expectResult(!(state.acceptsAuthentication(target: computer, enrolling: true)))
    }

    @Test func expiredSubscriptionSetupCannotBecomeReady() {
        var state = BluetoothAuthenticationState()
        state.connected(now: 0)
        state.discoveredServices()
        state.discoveredCharacteristics()
        expectResult(state.verifyComputer(computer, expected: computer, enrolling: false, now: 1))
        expectResult(!(state.subscriptions(challenge: true, result: true, now: 10)))
    }

    @Test func oldRSSIRemainsInFlightButCannotApproveNewGeneration() {
        var state = readyState()
        let oldRequest = UUID()
        let newRequest = UUID()
        let old = state.beginRSSI(requestID: oldRequest, now: 2)
        expectResult((old) != nil)
        expectResult(state.invalidateServices(now: 2.1))
        expectResult((state.rssiRead) == (old))
        state.discoveredServices()
        state.discoveredCharacteristics()
        expectResult(state.verifyComputer(computer, expected: computer, enrolling: false, now: 2.2))
        expectResult(state.subscriptions(challenge: true, result: true, now: 2.2))
        expectResult((state.beginRSSI(requestID: newRequest, now: 2.3)) == nil)
        expectResult((state.finishRSSI(now: 2.4, requestID: newRequest)) == nil)
        let fresh = state.beginRSSI(requestID: newRequest, now: 2.5)
        expectResult((fresh) != nil)
        expectResult((state.finishRSSI(now: 2.6, requestID: newRequest)) == (fresh))
    }

    @Test func lateOrWrongRequestRSSICannotBeUsed() {
        var state = readyState()
        let id = UUID()
        expectResult((state.beginRSSI(requestID: id, now: 2)) != nil)
        expectResult((state.finishRSSI(now: 5, requestID: id)) == nil)
        expectResult((state.beginRSSI(requestID: id, now: 6)) != nil)
        expectResult((state.finishRSSI(now: 6.1, requestID: UUID())) == nil)
        expectResult((state.beginRSSI(requestID: id, now: 7)) != nil)
        state.disconnected()
        expectResult((state.rssiRead) == nil)
        expectResult((state.finishRSSI(now: 7.1, requestID: id)) == nil)
    }

    @Test func stableIdentityDoesNotDependOnNameOrPeripheralUUID() throws {
        let old = RegisteredComputer(computerID: computer, name: "Windows", peripheralID: UUID())
        let changed = RegisteredComputer(computerID: computer, name: "Renamed", peripheralID: UUID())
        expectResult((old.peripheralID) != (changed.peripheralID))
        var state = BluetoothAuthenticationState()
        state.connected(now: 0)
        state.discoveredServices()
        state.discoveredCharacteristics()
        expectResult(state.verifyComputer(changed.computerID, expected: old.computerID, enrolling: false, now: 1))
        expectResult((try JSONDecoder().decode(RegisteredComputer.self,
            from: JSONEncoder().encode(changed))) == (changed))
        expectResult((BluetoothAuthenticationState.computerID(from: Data(computer.uuidString.lowercased().utf8))) == (computer))
        expectResult((BluetoothAuthenticationState.computerID(from: Data(computer.uuidString.utf8))) == (computer))
        for bad in ["", "Windows", "{\(computer)}", "00000000-0000-0000-0000-000000000000"] {
            expectResult((BluetoothAuthenticationState.computerID(from: Data(bad.utf8))) == nil)
        }
    }

    @Test func enrollmentResultsAreNotAuthenticationResults() {
        for code in ["enrollment_saved", "enrollment_already_registered"] {
            expectResult((BluetoothAuthenticationState.enrollmentOutcome(code: code, detail: nil)) == (.succeeded))
        }
        expectResult((BluetoothAuthenticationState.enrollmentOutcome(code: "enrollment_cancelled", detail: nil)) == (.cancelled))
        for code in ["enrollment_rejected", "enrollment_busy", "enrollment_expired", "enrollment_error", "enrollment_removed"] {
            expectResult((BluetoothAuthenticationState.enrollmentOutcome(code: code, detail: nil)) != (.succeeded))
        }
        expectResult((BluetoothAuthenticationState.enrollmentOutcome(code: "enrollment_saved",
            detail: "saved_reload_failed")) != (.succeeded))
        expectResult((BluetoothAuthenticationState.enrollmentOutcome(code: "unlock_approved", detail: nil)) == nil)
        expectResult((BluetoothAuthenticationState.enrollmentOutcome(code: "unknown", detail: "saved_reload_failed")) == nil)
    }

    @Test func oldOrUnassociatedAuthenticationResultsCannotMatch() {
        let old = UUID()
        let current = UUID()
        expectResult(!(BluetoothAuthenticationState.acceptsResult(requestID: nil, pending: nil, awaiting: nil)))
        expectResult(!(BluetoothAuthenticationState.acceptsResult(requestID: old, pending: current, awaiting: nil)))
        expectResult(!(BluetoothAuthenticationState.acceptsResult(requestID: old, pending: nil, awaiting: current)))
        expectResult(BluetoothAuthenticationState.acceptsResult(requestID: current, pending: current, awaiting: nil))
        expectResult(BluetoothAuthenticationState.acceptsResult(requestID: current, pending: nil, awaiting: current))
    }

    @Test func failedEnrollmentDoesNotOfferReplacementTarget() {
        let old = RegisteredComputer(computerID: computer, name: "Original", peripheralID: UUID())
        let candidate = RegisteredComputer(computerID: otherComputer, name: "Candidate", peripheralID: UUID())
        var snapshot = BluetoothViewState()
        snapshot.target = old
        for outcome in [ComputerEnrollmentState.cancelled, .rejected("rejected"), .failed("reload failed")] {
            expectResult((snapshot.completeEnrollment(outcome, candidate: candidate)) == nil)
            expectResult((snapshot.target) == (old))
        }
        expectResult((snapshot.completeEnrollment(.succeeded, candidate: candidate)) == (candidate))
        expectResult((snapshot.target) == (old))
    }

    @Test func oldWriteGenerationCannotAffectRecoveredConnection() {
        var state = readyState()
        let oldGeneration = state.generation
        expectResult(state.isCurrentGeneration(oldGeneration))
        _ = state.invalidateServices(now: 2)
        expectResult(!(state.isCurrentGeneration(oldGeneration)))
        expectResult(state.isCurrentGeneration(state.generation))
    }

    @Test func snapshotSeparatesConnectionEnrollmentAndAuthentication() {
        var snapshot = BluetoothViewState()
        snapshot.connection = .ready
        snapshot.enrollment = .rejected("Windows rejected pairing")
        snapshot.authentication = .rejected("Insufficient RSSI")
        expectResult((snapshot.connection) == (.ready))
        expectResult((String(localized: snapshot.enrollment.title)) == ("Windows rejected pairing"))
        expectResult((String(localized: snapshot.authentication.title)) == ("Insufficient RSSI"))
        expectResult((String(localized: PhoneAuthenticationState.approved.title)) == ("Request approved"))
    }

    @Test func serviceAbsenceClearsQualificationAndRequiresAdvertisement() {
        var state = readyState()
        let generation = state.generation
        state.serviceMissing()
        expectResult((state.phase) == (.waitingComputer))
        expectResult(state.requiresAdvertisement)
        expectResult((state.deadline) == nil)
        expectResult((state.verifiedComputerID) == nil)
        expectResult(!(state.challengeSubscribed))
        expectResult(!(state.resultSubscribed))
        expectResult((state.generation) > (generation))
        expectResult(!(state.acceptsAuthentication(target: computer, enrolling: false)))
    }

    @Test func waitingOvernightDoesNotStartTheInitializationDeadline() {
        var state = BluetoothAuthenticationState()
        state.waitForComputer()
        expectResult((state.deadline) == nil)
        expectResult(!(state.initializationExpired(now: 86_400)))
        expectResult(!(state.acceptsAuthentication(target: computer, enrolling: false)))
        state.connected(now: 86_400)
        expectResult((state.deadline) == (86_410))
        expectResult(!(state.initializationExpired(now: 86_409.999)))
        expectResult(state.initializationExpired(now: 86_410))
        expectResult((state.completeDiscoveryStep(now: 86_410)) == (.expired))
    }

    @Test func suspendedInitializationExpiresBeforeLateIdentityOrPreparation() {
        var state = BluetoothAuthenticationState()
        state.connected(now: 0)
        let generation = state.generation
        state.discoveredServices()
        state.discoveredCharacteristics()
        expectResult(state.initializationExpired(now: 61))
        expectResult(!(state.verifyComputer(computer, expected: computer, enrolling: false, now: 61)))
        expectResult(!(state.cacheReadyProbe(UUID(), generation: generation, now: 61)))
        expectResult(!(state.subscriptions(challenge: true, result: true, now: 61)))
        expectResult(!(state.acceptsAuthentication(target: computer, enrolling: false)))
    }

    @Test func preparationCannotFinishSuspendedSubscriptionInitialization() {
        var state = BluetoothAuthenticationState()
        let request = UUID()
        state.connected(now: 0)
        state.discoveredServices()
        state.discoveredCharacteristics()
        expectResult(state.verifyComputer(computer, expected: computer, enrolling: false, now: 1))
        expectResult(state.cacheReadyProbe(request, generation: state.generation, now: 2))
        expectResult(!(state.subscriptions(challenge: true, result: false, now: 3)))
        expectResult(state.initializationExpired(now: 61))
        expectResult(!(state.subscriptions(challenge: true, result: true, now: 61)))
        expectResult((state.beginReadyAcknowledgment(now: 61)) == nil)
        expectResult(!(state.acceptsPreparedChallenge(request, now: 61)))
    }

    @Test func failedInitializationClearsDeadlineAndAuthorization() {
        var state = readyState()
        state.failed()
        expectResult((state.deadline) == nil)
        expectResult(!(state.acceptsAuthentication(target: computer, enrolling: false)))
        state.connected(now: 100)
        expectResult((state.deadline) == (110))
        expectResult(!(state.invalidateServices(now: 109, discoveryPending: true)))
        expectResult((state.deadline) == (110))
        expectResult(!(state.initializationExpired(now: 109)))
        expectResult(state.initializationExpired(now: 110))
        expectResult((state.completeDiscoveryStep(now: 110)) == (.expired))
    }

    @Test func serviceReturnsAfterLongWaitAndNeedsFreshIdentityAndSubscriptions() {
        var state = readyState()
        state.serviceMissing()
        state.disconnected()
        state.connected(now: 20_000)
        expectResult((state.deadline) == (20_010))
        expectResult(!(state.subscriptions(challenge: true, result: true, now: 20_001)))
        state.discoveredServices()
        state.discoveredCharacteristics()
        expectResult(!(state.verifyComputer(otherComputer, expected: computer, enrolling: false, now: 20_001)))
        expectResult(state.verifyComputer(computer, expected: computer, enrolling: false, now: 20_001))
        expectResult(!(state.subscriptions(challenge: true, result: false, now: 20_002)))
        expectResult(state.subscriptions(challenge: true, result: true, now: 20_003))
    }

    @Test func waitingInvalidatesOldRSSIAndWriteGeneration() {
        var state = readyState()
        let request = UUID()
        let oldGeneration = state.generation
        let oldRead = state.beginRSSI(requestID: request, now: 2)
        state.serviceMissing()
        expectResult((state.rssiRead) == (oldRead))
        expectResult(!(state.isCurrentGeneration(oldGeneration)))
        expectResult((state.finishRSSI(now: 2.1, requestID: request)) == nil)
        expectResult((state.beginRSSI(requestID: UUID(), now: 2.2)) == nil)
        state.waitForComputer()
        expectResult(!(state.acceptsAuthentication(target: computer, enrolling: false)))
    }

    @Test func waitingComputerTitleDoesNotClaimUnlockChannelReady() {
        var snapshot = BluetoothViewState()
        snapshot.connection = .waitingComputer
        expectResult((String(localized: snapshot.connection.title)) == ("Searching for PC"))
        expectResult((snapshot.connection.failure) == nil)
        snapshot.connection = .failed("Stage: subscriptions; waiting for PC recovery")
        expectResult((String(localized: snapshot.connection.title)) == ("Connection failed"))
        expectResult((snapshot.connection.failure) != nil)
    }

    @Test func missingServiceRestrictionSurvivesConnectionRelease() {
        var state = readyState()
        state.serviceMissing()
        state.failed()
        state.disconnected()
        state.waitForComputer()
        expectResult(state.requiresAdvertisement)
        expectResult((state.deadline) == nil)
        state.connected(now: 101)
        state.discoveredServices()
        state.discoveredCharacteristics()
        expectResult(state.verifyComputer(computer, expected: computer, enrolling: false, now: 101))
        expectResult(!(state.subscriptions(challenge: true, result: false, now: 102)))
        expectResult(state.requiresAdvertisement)
        expectResult(state.subscriptions(challenge: true, result: true, now: 103))
        expectResult(!(state.requiresAdvertisement))
    }

    @Test func earlyReadyProbeWaitsForIdentityAndBothSubscriptions() {
        var state = BluetoothAuthenticationState()
        let request = UUID()
        state.connected(now: 0)
        expectResult(state.cacheReadyProbe(request, generation: state.generation, now: 1))
        expectResult((state.beginReadyAcknowledgment(now: 1)) == nil)
        expectResult(!(state.acceptsPreparedChallenge(request, now: 1)))
        state.discoveredServices()
        state.discoveredCharacteristics()
        expectResult(state.verifyComputer(computer, expected: computer, enrolling: false, now: 1))
        expectResult(!(state.subscriptions(challenge: true, result: false, now: 2)))
        expectResult((state.beginReadyAcknowledgment(now: 2)) == nil)
        expectResult(state.subscriptions(challenge: true, result: true, now: 3))
        expectResult((state.beginReadyAcknowledgment(now: 3)) == (request))
        expectResult(state.acceptsPreparedChallenge(request, now: 3))
        expectResult(!(state.acceptsPreparedChallenge(UUID(), now: 3)))
    }

    @Test func duplicateProbeCannotExtendDeadlineOrQueueConcurrentWrites() {
        var state = readyState()
        let request = UUID()
        expectResult(state.cacheReadyProbe(request, generation: state.generation, now: 1))
        expectResult((state.beginReadyAcknowledgment(now: 2)) == (request))
        expectResult((state.beginReadyAcknowledgment(now: 2.1)) == nil)
        expectResult(!(state.cacheReadyProbe(UUID(), generation: state.generation, now: 2.1)))
        expectResult((state.readyProbe?.requestID) == (request))
        expectResult(state.cacheReadyProbe(request, generation: state.generation, now: 29))
        expectResult((state.readyProbe?.deadline) == (31))
        state.finishReadyAcknowledgment(request, generation: state.generation)
        expectResult((state.beginReadyAcknowledgment(now: 30)) == (request))
        expectResult(!(state.cacheReadyProbe(request, generation: state.generation, now: 31)))
        expectResult((state.beginReadyAcknowledgment(now: 31)) == nil)
        expectResult(!(state.acceptsPreparedChallenge(request, now: 31)))
    }

    @Test func serviceChangeAndCancellationDiscardPreparedRequest() {
        var state = readyState()
        let request = UUID()
        let generation = state.generation
        expectResult(state.cacheReadyProbe(request, generation: generation, now: 1))
        expectResult((state.beginReadyAcknowledgment(now: 2)) == (request))
        expectResult(state.invalidateServices(now: 3, discoveryPending: false))
        expectResult((state.readyProbe) == nil)
        expectResult(!(state.cacheReadyProbe(request, generation: generation, now: 4)))
        state.finishReadyAcknowledgment(request, generation: generation)
        expectResult(!(state.acceptsPreparedChallenge(request, now: 4)))
        state.connected(now: 5)
        expectResult(state.cacheReadyProbe(UUID(), generation: state.generation, now: 6))
        state.disconnected()
        expectResult((state.readyProbe) == nil)
        expectResult((state.beginReadyAcknowledgment(now: 7)) == nil)
    }

    @Test func oldReceiptCannotFinishNewPreparationWrite() {
        var state = readyState()
        let oldRequest = UUID()
        let newRequest = UUID()
        expectResult(state.cacheReadyProbe(oldRequest, generation: state.generation, now: 1))
        expectResult((state.beginReadyAcknowledgment(now: 1)) == (oldRequest))
        state.clearReadyProbe()
        expectResult(state.cacheReadyProbe(newRequest, generation: state.generation, now: 2))
        expectResult((state.beginReadyAcknowledgment(now: 2)) == (newRequest))
        state.finishReadyAcknowledgment(oldRequest, generation: state.generation)
        expectResult((state.beginReadyAcknowledgment(now: 2.1)) == nil)
        expectResult(!(state.acceptsPreparedChallenge(oldRequest, now: 2.1)))
        expectResult(state.acceptsPreparedChallenge(newRequest, now: 2.1))
        state.clearReadyProbe()
        expectResult(!(state.acceptsPreparedChallenge(newRequest, now: 2.2)))
    }

    @Test func historyAssociatesSignalWithCurrentRequest() {
        var history = AuthenticationHistory()
        let first = UUID()
        let second = UUID()
        history.begin(first)
        history.measured(-45, for: first)
        history.begin(second)
        history.measured(-40, for: first)
        history.complete(first, approved: true, at: Date())
        expectResult((history.result) == nil)
        history.measured(-55, for: second)
        let date = Date(timeIntervalSince1970: 100)
        history.complete(second, approved: true, at: date)
        expectResult((history.result?.requestID) == (second))
        expectResult((history.result?.approvedAt) == (date))
        expectResult((history.result?.rssi) == (-55))
    }

    @Test func failureClearsDisplayedApprovalAndCannotBecomeLateSuccess() {
        var history = AuthenticationHistory()
        let id = UUID()
        history.begin(id)
        history.measured(-80, for: id)
        history.complete(id, approved: false, at: Date())
        expectResult((history.result?.requestID) == (id))
        expectResult((history.result?.approvedAt) == nil)
        expectResult((history.result?.rssi) == nil)
        history.complete(id, approved: true, at: Date())
        expectResult((history.result?.approvedAt) == nil)
    }

    @Test func historyRestoresCompletedResultButNotPendingRequest() throws {
        let id = UUID()
        let date = Date(timeIntervalSince1970: 100)
        var history = AuthenticationHistory()
        history.begin(id)
        history.measured(-50, for: id)
        history.complete(id, approved: true, at: date)
        let original = try requireResult(history.result)
        let name = "AuthenticationHistoryTests.\(UUID())"
        let defaults = try requireResult(UserDefaults(suiteName: name))
        defer { defaults.removePersistentDomain(forName: name) }
        try history.save(to: defaults)
        var restarted = try AuthenticationHistory(defaults: defaults)
        expectResult((restarted.result) == (original))
        restarted.complete(id, approved: false, at: Date())
        expectResult((restarted.result) == (original))
        restarted.begin(UUID())
        expectResult((restarted.result) == (original))
    }

    @Test func forgetClearsHistoryAndRejectsLateRequestCallbacks() {
        var history = AuthenticationHistory()
        let id = UUID()
        history.begin(id)
        history.measured(-50, for: id)
        history.forget()
        history.measured(-45, for: id)
        history.complete(id, approved: true, at: Date())
        expectResult((history.result) == nil)
        var snapshot = BluetoothViewState()
        let target = RegisteredComputer(computerID: computer, name: "PC", peripheralID: UUID())
        snapshot.target = target
        snapshot.connectedComputer = target
        snapshot.threshold = -70
        snapshot.rssi = -45
        snapshot.rssiMeasuredAt = Date()
        snapshot.lastResult = .init(requestID: id, approvedAt: Date(), rssi: -45)
        snapshot.forgetComputer()
        expectResult((snapshot.target) == nil)
        expectResult((snapshot.connectedComputer) == nil)
        expectResult((snapshot.lastResult) == nil)
        expectResult((snapshot.rssi) == nil)
        expectResult((snapshot.rssiMeasuredAt) == nil)
        expectResult((snapshot.threshold) == (-70))
        expectResult((snapshot.connection) == (.unregistered))
        expectResult((snapshot.authentication) == (.waiting))
        let policy = readyState()
        expectResult(!(policy.acceptsAuthentication(target: snapshot.target?.computerID, enrolling: false)))
        expectResult(policy.acceptsAuthentication(target: computer, enrolling: false))
    }


    @Test func storedFailureAndForgetSurviveRestart() throws {
        let name = "AuthenticationHistoryRemovalTests.\(UUID())"
        let defaults = try requireResult(UserDefaults(suiteName: name))
        defer { defaults.removePersistentDomain(forName: name) }
        var history = AuthenticationHistory()
        let id = UUID()
        history.begin(id)
        history.complete(id, approved: false, at: Date())
        try history.save(to: defaults)
        var restarted = try AuthenticationHistory(defaults: defaults)
        expectResult((restarted.result?.requestID) == (id))
        expectResult((restarted.result?.approvedAt) == nil)
        expectResult((restarted.result?.rssi) == nil)
        restarted.forget()
        try restarted.save(to: defaults)
        expectResult((defaults.data(forKey: AuthenticationHistory.storageKey)) == nil)
        expectResult((try AuthenticationHistory(defaults: defaults).result) == nil)
    }

    @Test func unreadableStoredHistoryReportsError() throws {
        let name = "AuthenticationHistoryInvalidTests.\(UUID())"
        let defaults = try requireResult(UserDefaults(suiteName: name))
        defer { defaults.removePersistentDomain(forName: name) }
        defaults.set(Data("invalid".utf8), forKey: AuthenticationHistory.storageKey)
        #expect(throws: (any Error).self) {
            try AuthenticationHistory(defaults: defaults)
        }
    }

}
