// Created by Rui MA on 03 Oct 2026

import Foundation

struct RegisteredComputer: Codable, Equatable {
    static let storageKey = "registeredWindowsComputer"
    let computerID: UUID
    var name: String
    var peripheralID: UUID
}

enum BluetoothConnectionState: Equatable {
    case unregistered, bluetoothUnavailable, waitingComputer, connecting
    case discovering, verifyingComputer, subscribing, ready, recovering
    case failed(String)

    var title: LocalizedStringResource {
        switch self {
        case .unregistered: "No Paired PC"
        case .bluetoothUnavailable: "Bluetooth unavailable"
        case .waitingComputer: "Searching for PC"
        case .connecting: "Connecting"
        case .discovering: "Preparing connection"
        case .verifyingComputer: "Verifying PC"
        case .subscribing: "Preparing connection"
        case .ready: "Ready"
        case .recovering: "Reconnecting"
        case .failed: "Connection failed"
        }
    }

    var failure: String? {
        if case let .failed(message) = self { return message }
        return nil
    }
}

enum ComputerEnrollmentState: Equatable {
    case idle, searching, waitingConfirmation, succeeded, cancelled
    case rejected(String), failed(String)

    var isActive: Bool { self == .searching || self == .waitingConfirmation }
    var title: LocalizedStringResource {
        switch self {
        case .idle: "Not pairing"
        case .searching: "Searching for Windows pairing"
        case .waitingConfirmation: "Waiting for confirmation on Windows"
        case .succeeded: "PC paired"
        case .cancelled: "Pairing cancelled. The previous PC was kept."
        case let .rejected(message), let .failed(message): "\(message)"
        }
    }
}

enum PhoneAuthenticationState: Equatable {
    case waiting, readingRSSI, signing, awaitingWindows, approved
    case rejected(String)

    var title: LocalizedStringResource {
        switch self {
        case .waiting: "Waiting for request"
        case .readingRSSI: "Checking signal"
        case .signing: "Authenticating"
        case .awaitingWindows: "Waiting for Windows"
        case .approved: "Request approved"
        case let .rejected(message): "\(message)"
        }
    }
}

struct BluetoothViewState: Equatable {
    var connection: BluetoothConnectionState = .unregistered
    var enrollment: ComputerEnrollmentState = .idle
    var authentication: PhoneAuthenticationState = .waiting
    var target: RegisteredComputer?
    var connectedComputer: RegisteredComputer?
    static let thresholdRange = -100 ... -20
    var threshold = -60
    var rssi: Int?
    var rssiMeasuredAt: Date?
    var issue: String?
    var lastResult: AuthenticationHistory.Result?

    mutating func forgetComputer() {
        target = nil
        connectedComputer = nil
        lastResult = nil
        rssi = nil
        rssiMeasuredAt = nil
        enrollment = .idle
        authentication = .waiting
        issue = nil
        connection = .unregistered
    }

    mutating func completeEnrollment(_ outcome: ComputerEnrollmentState,
                                     candidate: RegisteredComputer) -> RegisteredComputer? {
        enrollment = outcome
        return outcome == .succeeded ? candidate : nil
    }
}

struct BluetoothAuthenticationState {
    enum SignalDecision: Equatable { case approve, tooLow, invalid, expired }
    enum Phase: Equatable {
        case idle, waitingComputer, services, characteristics, identity, subscriptions, ready, failed
    }
    enum Completion: Equatable { case proceed, rediscover, expired }
    struct RSSIRead: Equatable {
        let sequence: UInt64
        let generation: UInt64
        let requestID: UUID
        let deadline: TimeInterval
    }
    struct ReadyProbe: Equatable {
        let requestID: UUID
        let generation: UInt64
        let deadline: TimeInterval
        var writePending = false
        var acknowledgmentIssued = false
    }

    static let responseLifetime: TimeInterval = 3
    static let initializationLifetime: TimeInterval = 10
    private(set) var phase: Phase = .idle
    private(set) var generation: UInt64 = 0
    private(set) var deadline: TimeInterval?
    private(set) var rediscoveryRequested = false
    private(set) var verifiedComputerID: UUID?
    private(set) var challengeSubscribed = false
    private(set) var resultSubscribed = false
    private(set) var rssiRead: RSSIRead?
    private(set) var requiresAdvertisement = false
    private(set) var readyProbe: ReadyProbe?
    private var rssiSequence: UInt64 = 0

    func initializationExpired(now: TimeInterval) -> Bool {
        deadline.map { now >= $0 } ?? false
    }

    static func signalDecision(rssi: Int, threshold: Int, now: TimeInterval,
                               deadline: TimeInterval) -> SignalDecision {
        guard now < deadline else { return .expired }
        guard rssi < 0, rssi >= -127 else { return .invalid }
        return rssi >= threshold ? .approve : .tooLow
    }

    static func computerID(from data: Data) -> UUID? {
        guard data.count == 36, let text = String(data: data, encoding: .utf8),
              let id = UUID(uuidString: text), id.uuidString.lowercased() == text.lowercased(),
              id != UUID(uuid: (0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0)) else { return nil }
        return id
    }

    static func enrollmentOutcome(code: String, detail: String?) -> ComputerEnrollmentState? {
        let outcome: ComputerEnrollmentState
        switch code {
        case "enrollment_saved", "enrollment_already_registered": outcome = .succeeded
        case "enrollment_cancelled": outcome = .cancelled
        case "enrollment_rejected": outcome = .rejected(String(localized: "Windows rejected pairing. Open Pair iPhone from the Windows tray."))
        case "enrollment_busy": outcome = .rejected(String(localized: "Windows is processing another pairing request."))
        case "enrollment_expired": outcome = .failed(String(localized: "The Windows pairing window expired."))
        case "enrollment_error": outcome = .failed(String(localized: "Windows pairing failed."))
        case "enrollment_removed": outcome = .failed(String(localized: "Windows removed the authorization. Forget this PC and pair again."))
        default: return nil
        }
        return detail == "saved_reload_failed"
            ? .failed(String(localized: "Windows saved the pairing change, but the service could not reload. Check Windows and try again.")) : outcome
    }

    static func acceptsResult(requestID: UUID?, pending: UUID?, awaiting: UUID?) -> Bool {
        guard let requestID else { return false }
        return requestID == pending || requestID == awaiting
    }

    mutating func connected(now: TimeInterval) {
        resetTransport()
        phase = .services
        deadline = now + Self.initializationLifetime
    }

    mutating func waitForComputer() {
        resetTransport()
        phase = .waitingComputer
    }

    mutating func serviceMissing() {
        resetTransport()
        phase = .waitingComputer
        requiresAdvertisement = true
    }

    mutating func allowRememberedConnection() { requiresAdvertisement = false }

    mutating func cacheReadyProbe(_ requestID: UUID, generation: UInt64, now: TimeInterval) -> Bool {
        guard generation == self.generation,
              !initializationExpired(now: now),
              [.services, .characteristics, .identity, .subscriptions, .ready].contains(phase),
              requestID != UUID(uuid: (0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0)) else { return false }
        if let readyProbe, readyProbe.requestID == requestID {
            return now < readyProbe.deadline
        }
        if let readyProbe, readyProbe.acknowledgmentIssued, now < readyProbe.deadline { return false }
        readyProbe = ReadyProbe(requestID: requestID, generation: generation, deadline: now + 30)
        return true
    }

    mutating func beginReadyAcknowledgment(now: TimeInterval) -> UUID? {
        guard phase == .ready, verifiedComputerID != nil, challengeSubscribed, resultSubscribed,
              let probe = readyProbe, probe.generation == generation, now < probe.deadline,
              !probe.writePending else { return nil }
        readyProbe?.writePending = true
        readyProbe?.acknowledgmentIssued = true
        return probe.requestID
    }

    mutating func finishReadyAcknowledgment(_ requestID: UUID, generation: UInt64) {
        guard generation == self.generation, readyProbe?.requestID == requestID else { return }
        readyProbe?.writePending = false
    }

    func acceptsPreparedChallenge(_ requestID: UUID, now: TimeInterval) -> Bool {
        guard let probe = readyProbe else { return false }
        return phase == .ready && probe.generation == generation && probe.requestID == requestID &&
            probe.acknowledgmentIssued && now < probe.deadline
    }

    mutating func clearReadyProbe() { readyProbe = nil }

    mutating func invalidateServices(now: TimeInterval, discoveryPending: Bool? = nil) -> Bool {
        generation &+= 1
        clearReadyProbe()
        verifiedComputerID = nil
        challengeSubscribed = false
        resultSubscribed = false
        if deadline == nil { deadline = now + Self.initializationLifetime }
        if discoveryPending ?? (phase == .services || phase == .characteristics || phase == .identity) {
            rediscoveryRequested = true
            return false
        }
        phase = .services
        rediscoveryRequested = false
        return true
    }

    mutating func completeDiscoveryStep(now: TimeInterval) -> Completion {
        guard let deadline, now < deadline else { return .expired }
        if rediscoveryRequested {
            rediscoveryRequested = false
            phase = .services
            return .rediscover
        }
        return .proceed
    }

    mutating func discoveredServices() { phase = .characteristics }
    mutating func discoveredCharacteristics() { phase = .identity }

    mutating func verifyComputer(_ id: UUID, expected: UUID?, enrolling: Bool, now: TimeInterval) -> Bool {
        guard phase == .identity, let deadline, now < deadline,
              enrolling || id == expected else { return false }
        verifiedComputerID = id
        phase = .subscriptions
        return true
    }

    @discardableResult
    mutating func subscriptions(challenge: Bool, result: Bool, now: TimeInterval) -> Bool {
        guard phase == .subscriptions, verifiedComputerID != nil,
              let deadline, now < deadline else { return false }
        challengeSubscribed = challenge
        resultSubscribed = result
        guard challenge && result else { return false }
        phase = .ready
        self.deadline = nil
        requiresAdvertisement = false
        return true
    }

    func acceptsAuthentication(target: UUID?, enrolling: Bool) -> Bool {
        phase == .ready && verifiedComputerID == target && target != nil && !enrolling
    }

    func isCurrentGeneration(_ value: UInt64) -> Bool { value == generation }

    mutating func beginRSSI(requestID: UUID, now: TimeInterval) -> RSSIRead? {
        guard phase == .ready, rssiRead == nil else { return nil }
        rssiSequence &+= 1
        let read = RSSIRead(sequence: rssiSequence, generation: generation,
                            requestID: requestID, deadline: now + Self.responseLifetime)
        rssiRead = read
        return read
    }

    mutating func finishRSSI(now: TimeInterval, requestID: UUID?) -> RSSIRead? {
        guard let read = rssiRead else { return nil }
        rssiRead = nil
        guard read.generation == generation, read.requestID == requestID, now < read.deadline,
              phase == .ready else { return nil }
        return read
    }

    mutating func resetTransport() {
        generation &+= 1
        clearReadyProbe()
        phase = .idle
        deadline = nil
        rediscoveryRequested = false
        verifiedComputerID = nil
        challengeSubscribed = false
        resultSubscribed = false
    }

    mutating func disconnected() {
        resetTransport()
        rssiRead = nil
    }

    mutating func failed() {
        resetTransport()
        phase = .failed
    }
}

struct AuthenticationHistory {
    struct Result: Codable, Equatable {
        let requestID: UUID
        let approvedAt: Date?
        let rssi: Int?
    }

    static let storageKey = "lastWindowsAuthenticationResult"
    private(set) var result: Result?
    private var requestID: UUID?
    private var signal: Int?

    init(result: Result? = nil) { self.result = result }

    init(defaults: UserDefaults) throws {
        if let data = defaults.data(forKey: Self.storageKey) {
            result = try JSONDecoder().decode(Result.self, from: data)
        }
    }

    func save(to defaults: UserDefaults) throws {
        if let result {
            defaults.set(try JSONEncoder().encode(result), forKey: Self.storageKey)
        } else { defaults.removeObject(forKey: Self.storageKey) }
    }

    mutating func begin(_ id: UUID) {
        requestID = id
        signal = nil
    }

    mutating func measured(_ value: Int, for id: UUID) {
        guard requestID == id else { return }
        signal = value
    }

    mutating func complete(_ id: UUID?, approved: Bool, at date: Date) {
        guard let id, requestID == id else { return }
        result = Result(requestID: id, approvedAt: approved ? date : nil,
                        rssi: approved ? signal : nil)
        requestID = nil
        signal = nil
    }

    mutating func forget() {
        result = nil
        requestID = nil
        signal = nil
    }
}
