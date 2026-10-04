// Created by Rui MA on 04 Oct 2026

import Foundation

struct BluetoothConnectionRecovery {
    enum Source: Equatable { case advertisement, remembered, restoration }
    enum Stage: Equatable { case waiting, connected, initializing, ready, cancelling }
    struct Attempt: Equatable {
        let peripheralID: UUID
        let generation: UInt64
        var stage: Stage = .waiting
        var remainingRetries = 1
        var connectionRequested = false
    }

    static let maximumAttempts = 16
    private(set) var attempts: [UUID: Attempt] = [:]
    private(set) var activeID: UUID?
    private(set) var scanRound: UInt64 = 0
    private var sequence: UInt64 = 0
    private var rejectedIDs: [UUID] = []
    private var failedCachedIDs: [UUID] = []

    mutating func beginScanRound() {
        scanRound &+= 1
        rejectedIDs.removeAll()
    }

    mutating func begin(_ id: UUID, source: Source) -> Attempt? {
        guard attempts[id] == nil, attempts.count < Self.maximumAttempts,
              !rejectedIDs.contains(id), source != .remembered || !failedCachedIDs.contains(id) else { return nil }
        if source == .advertisement { failedCachedIDs.removeAll { $0 == id } }
        sequence &+= 1
        let attempt = Attempt(peripheralID: id, generation: sequence)
        attempts[id] = attempt
        return attempt
    }

    mutating func connected(_ id: UUID, generation: UInt64) -> Bool {
        guard let attempt = attempts[id], attempt.generation == generation,
              attempt.stage == .waiting else { return false }
        attempts[id]?.stage = .connected
        return true
    }

    mutating func request(_ id: UUID, generation: UInt64) -> Bool {
        guard let attempt = attempts[id], attempt.generation == generation,
              attempt.stage == .waiting, !attempt.connectionRequested else { return false }
        attempts[id]?.connectionRequested = true
        return true
    }

    mutating func selectConnected(preferred: UUID?, available: Set<UUID>) -> Attempt? {
        guard activeID == nil else { return nil }
        let connected = attempts.values.filter { $0.stage == .connected && available.contains($0.peripheralID) }
        guard let attempt = connected.first(where: { $0.peripheralID == preferred }) ??
            connected.min(by: { $0.generation < $1.generation }) else { return nil }
        activeID = attempt.peripheralID
        attempts[attempt.peripheralID]?.stage = .initializing
        return attempts[attempt.peripheralID]
    }

    mutating func ready(_ id: UUID) {
        guard activeID == id, attempts[id]?.stage == .initializing else { return }
        attempts[id]?.stage = .ready
        attempts[id]?.remainingRetries = 1
    }

    mutating func restartInitialization(_ id: UUID) {
        guard activeID == id, attempts[id]?.stage == .ready else { return }
        attempts[id]?.stage = .initializing
        attempts[id]?.remainingRetries = 1
    }

    mutating func cancel(_ id: UUID) -> Bool {
        guard let attempt = attempts[id], attempt.stage != .cancelling else { return false }
        attempts[id]?.stage = .cancelling
        return true
    }

    mutating func finish(_ id: UUID, generation: UInt64) -> Attempt? {
        guard let attempt = attempts[id], attempt.generation == generation else { return nil }
        attempts.removeValue(forKey: id)
        if activeID == id { activeID = nil }
        return attempt
    }

    mutating func retry(_ completed: Attempt) -> Attempt? {
        guard completed.remainingRetries > 0, attempts[completed.peripheralID] == nil,
              attempts.count < Self.maximumAttempts, !rejectedIDs.contains(completed.peripheralID) else { return nil }
        sequence &+= 1
        let attempt = Attempt(peripheralID: completed.peripheralID, generation: sequence,
                              remainingRetries: completed.remainingRetries - 1)
        attempts[attempt.peripheralID] = attempt
        return attempt
    }

    mutating func failed(_ id: UUID) {
        if !failedCachedIDs.contains(id) {
            if failedCachedIDs.count == 64 { failedCachedIDs.removeFirst() }
            failedCachedIDs.append(id)
        }
    }

    mutating func reject(_ id: UUID) {
        if !rejectedIDs.contains(id) {
            if rejectedIDs.count == 64 { rejectedIDs.removeFirst() }
            rejectedIDs.append(id)
        }
        failed(id)
    }

    mutating func allowRemembered(_ id: UUID) { failedCachedIDs.removeAll { $0 == id } }

    mutating func reset() {
        attempts.removeAll()
        activeID = nil
        rejectedIDs.removeAll()
        failedCachedIDs.removeAll()
    }
}
