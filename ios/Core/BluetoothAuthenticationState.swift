// Created by Rui MA on 03 Oct 2026

import Foundation

struct RegisteredComputer: Codable, Equatable {
    let computerID: UUID
    var name: String
    var peripheralID: UUID
}

enum BluetoothConnectionState: Equatable {
    case unregistered, bluetoothUnavailable, waitingComputer, connecting
    case discovering, verifyingComputer, subscribing, ready, recovering
    case failed(String)

    var title: String {
        switch self {
        case .unregistered: "尚未登记电脑"
        case .bluetoothUnavailable: "蓝牙不可用"
        case .waitingComputer: "等待目标电脑广播"
        case .connecting: "正在建立蓝牙连接"
        case .discovering: "正在发现解锁服务"
        case .verifyingComputer: "正在核对目标电脑"
        case .subscribing: "正在准备通知订阅"
        case .ready: "已连接，解锁通道就绪"
        case .recovering: "正在恢复解锁服务"
        case .failed: "通道初始化异常"
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
    var title: String {
        switch self {
        case .idle: "未进行登记"
        case .searching: "寻找 Windows 配对窗口"
        case .waitingConfirmation: "等待 Windows 指纹确认"
        case .succeeded: "电脑登记成功"
        case .cancelled: "登记已取消，原目标保留"
        case let .rejected(message), let .failed(message): message
        }
    }
}

enum PhoneAuthenticationState: Equatable {
    case waiting, paused, readingRSSI, signing, awaitingWindows, approved
    case rejected(String)

    var title: String {
        switch self {
        case .waiting: "等待 Windows 请求"
        case .paused: "自动响应已暂停"
        case .readingRSSI: "正在读取本次请求的新 RSSI"
        case .signing: "正在签名"
        case .awaitingWindows: "签名已发送，等待 Windows 结果"
        case .approved: "Windows 已批准，等待电脑完成解锁"
        case let .rejected(message): message
        }
    }
}

struct BluetoothViewState: Equatable {
    var connection: BluetoothConnectionState = .unregistered
    var enrollment: ComputerEnrollmentState = .idle
    var authentication: PhoneAuthenticationState = .waiting
    var target: RegisteredComputer?
    var connectedComputer: RegisteredComputer?
    var automaticEnabled = true
    var threshold = -60
    var rssi: Int?
    var rssiMeasuredAt: Date?
    var issue: String?

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

    static func automaticPreference(_ defaults: UserDefaults) -> Bool {
        if defaults.integer(forKey: "automaticUnlockPreferenceVersion") < 2 {
            defaults.set(true, forKey: "automaticUnlockEnabled")
            defaults.set(2, forKey: "automaticUnlockPreferenceVersion")
        }
        return defaults.bool(forKey: "automaticUnlockEnabled")
    }

    static func computerID(from data: Data) -> UUID? {
        guard data.count == 36, let text = String(data: data, encoding: .utf8),
              let id = UUID(uuidString: text), id.uuidString.lowercased() == text.lowercased(),
              id != UUID(uuid: (0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0)) else { return nil }
        return id
    }

    static func enrollmentOutcome(code: String, detail: String?) -> ComputerEnrollmentState? {
        let knownCodes = ["enrollment_saved", "enrollment_already_registered", "enrollment_cancelled",
                          "enrollment_rejected", "enrollment_busy", "enrollment_expired",
                          "enrollment_error", "enrollment_removed"]
        guard knownCodes.contains(code) else { return nil }
        if detail == "saved_reload_failed" {
            return .failed("Windows 登记已修改，但服务重新加载失败；请在 Windows 检查后重试")
        }
        switch code {
        case "enrollment_saved", "enrollment_already_registered": return .succeeded
        case "enrollment_cancelled": return .cancelled
        case "enrollment_rejected": return .rejected("Windows 拒绝登记，请先开启托盘配对窗口")
        case "enrollment_busy": return .rejected("Windows 正在处理另一份登记")
        case "enrollment_expired": return .failed("Windows 配对窗口已过期")
        case "enrollment_error": return .failed("Windows 登记失败")
        case "enrollment_removed": return .failed("Windows 已移除登记，请重新登记")
        default: return nil
        }
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

    func acceptsAuthentication(target: UUID?, enabled: Bool, enrolling: Bool) -> Bool {
        phase == .ready && verifiedComputerID == target && target != nil && enabled && !enrolling
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
