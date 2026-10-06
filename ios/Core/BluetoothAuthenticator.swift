// Created by Rui MA on 26 Sep 2026

@preconcurrency import CoreBluetooth
import Foundation
import OSLog

@MainActor
final class BluetoothAuthenticator: NSObject, @preconcurrency CBCentralManagerDelegate, @preconcurrency CBPeripheralDelegate {
    static let serviceUUID = CBUUID(string: "F1E2D3C4-B5A6-4789-8012-3456789ABCDE")
    static let requestCharacteristicUUID = CBUUID(string: "F1E2D3C4-B5A6-4789-8012-3456789ABCD1")
    static let challengeCharacteristicUUID = CBUUID(string: "F1E2D3C4-B5A6-4789-8012-3456789ABCD2")
    static let assertionCharacteristicUUID = CBUUID(string: "F1E2D3C4-B5A6-4789-8012-3456789ABCD3")
    static let resultCharacteristicUUID = CBUUID(string: "F1E2D3C4-B5A6-4789-8012-3456789ABCD4")
    static let computerIDCharacteristicUUID = CBUUID(string: "F1E2D3C4-B5A6-4789-8012-3456789ABCD5")

    var onUpdate: ((BluetoothViewState) -> Void)?
    var onDiagnostic: ((String) -> Void)?
    private(set) var viewState = BluetoothViewState()
    private let keyStore: SecureEnclaveKeyStore
    private let defaults: UserDefaults
    private let logger = Logger(subsystem: Bundle.main.bundleIdentifier ?? "iPhoneUnlock", category: "BluetoothUnlock")
    private let diagnosticClock = ISO8601DateFormatter()
    private var policy = BluetoothAuthenticationState()
    private var recovery = BluetoothConnectionRecovery()
    private var connectionPeripherals: [UUID: CBPeripheral] = [:]
    private var deferredAdvertisements: [UUID: CBPeripheral] = [:]
    private lazy var centralManager = CBCentralManager(delegate: self, queue: nil,
        options: [CBCentralManagerOptionRestoreIdentifierKey: "com.example.unlock-windows-with-iphone.central"])
    private var peripheral: CBPeripheral?
    private var rememberedPeripheral: CBPeripheral?
    private var rememberedTargetRejected = false
    private var serviceInDiscovery: CBService?
    private var identityReadInDiscovery: CBCharacteristic?
    private enum DiscoveryOperation: Equatable { case services, characteristics, identity }
    private var discoveryOperation: DiscoveryOperation?
    private var requestCharacteristic: CBCharacteristic?
    private var challengeCharacteristic: CBCharacteristic?
    private var assertionCharacteristic: CBCharacteristic?
    private var resultCharacteristic: CBCharacteristic?
    private var enrolling = false
    private var enrollmentSent = false
    private var enrollmentSequence: UInt64 = 0
    private enum WritePurpose { case enrollment(UInt64), assertion(UUID), rejection(UUID), readyAcknowledgment(UUID) }
    private struct WriteContext {
        let characteristic: CBCharacteristic
        let generation: UInt64
        let purpose: WritePurpose
    }
    private var writes: [ObjectIdentifier: [WriteContext]] = [:]
    private var history = AuthenticationHistory()
    private var persistedResult: AuthenticationHistory.Result?
    private var foreground = false
    private var pendingChallenge: UnlockChallenge?
    private var pendingDeadline = 0.0
    private var awaitingResultID: UUID?
    private var lastHandledRequest: UUID?
    private var initializationTimeout: Task<Void, Never>?
    private var authenticationTimeout: Task<Void, Never>?
    private var rssiTimeout: Task<Void, Never>?
    private enum DisconnectAction: Equatable { case recover, search, resume, halt, advertisement }
    private var disconnectAction: DisconnectAction?

    private var shouldConnect: Bool {
        enrolling || viewState.target != nil
    }
    private var now: TimeInterval { ProcessInfo.processInfo.systemUptime }

    init(keyStore: SecureEnclaveKeyStore, defaults: UserDefaults = .standard) {
        self.keyStore = keyStore
        self.defaults = defaults
        super.init()
        diagnosticClock.formatOptions = [.withInternetDateTime, .withFractionalSeconds]
        diagnosticClock.timeZone = TimeZone(secondsFromGMT: 0)
        viewState.threshold = defaults.object(forKey: "unlockRSSIThreshold") as? Int ?? viewState.threshold
        if let data = defaults.data(forKey: RegisteredComputer.storageKey) {
            do { viewState.target = try JSONDecoder().decode(RegisteredComputer.self, from: data) }
            catch { viewState.issue = String(localized: "Saved PC information could not be read. Add your PC again.") }
        }
        if viewState.target != nil {
            do {
                history = try AuthenticationHistory(defaults: defaults)
                persistedResult = history.result
                viewState.lastResult = history.result
            } catch { viewState.issue = String(localized: "Saved request history could not be read: \(error.localizedDescription)") }
        }
    }

    func activate() { publish(); _ = centralManager }

    func forgetComputer() {
        enrolling = false
        enrollmentSent = false
        enrollmentSequence &+= 1
        history.forget()
        persistedResult = nil
        defaults.removeObject(forKey: RegisteredComputer.storageKey)
        defaults.removeObject(forKey: AuthenticationHistory.storageKey)
        viewState.forgetComputer()
        rememberedPeripheral = nil
        rememberedTargetRejected = false
        lastHandledRequest = nil
        finishPending()
        disconnect(action: .halt)
        viewState.authentication = .waiting
        publish()
    }

    func setThreshold(_ value: Int) {
        viewState.threshold = min(BluetoothViewState.thresholdRange.upperBound, max(BluetoothViewState.thresholdRange.lowerBound, value))
        defaults.set(viewState.threshold, forKey: "unlockRSSIThreshold")
        publish()
    }

    func retryConnection() {
        guard !enrolling else { return }
        guard disconnectAction == nil else {
            viewState.issue = String(localized: "The current connection is closing. Please wait.")
            publish()
            return
        }
        policy.allowRememberedConnection()
        rememberedTargetRejected = false
        if let target = viewState.target { recovery.allowRemembered(target.peripheralID) }
        centralManager.stopScan()
        deferredAdvertisements.removeAll()
        cancelOtherConnections()
        guard viewState.target != nil else {
            viewState.connection = .unregistered
            publish()
            return
        }
        viewState.issue = nil
        if let peripheral, peripheral.state == .connected, policy.phase == .ready { publish(); return }
        viewState.connection = .waitingComputer
        if peripheral != nil { disconnect(action: .resume) }
        else { beginSearch() }
    }

    func startEnrollment() {
        guard !viewState.enrollment.isActive else { return }
        guard disconnectAction == nil else {
            viewState.issue = String(localized: "The current connection is closing. Wait before pairing.")
            publish()
            return
        }
        discardAuthentication(message: String(localized: "Pairing started. The current authentication was cancelled."))
        enrolling = true
        enrollmentSent = false
        enrollmentSequence &+= 1
        centralManager.stopScan()
        deferredAdvertisements.removeAll()
        cancelOtherConnections()
        viewState.enrollment = .searching
        viewState.issue = nil
        if let peripheral, peripheral.state == .connected {
            rediscoverServices(peripheral, trigger: "explicit enrollment")
        } else if peripheral != nil { disconnect(action: .resume) }
        else { beginSearch() }
        publish()
    }

    func cancelEnrollment() {
        guard enrolling else { return }
        enrolling = false
        enrollmentSent = false
        viewState.enrollment = .cancelled
        disconnect(action: .resume)
        publish()
    }

    func setForeground(_ active: Bool) {
        let becameActive = active && !foreground
        foreground = active
        diagnostic("lifecycle foreground=\(active)")
        if active && expireInitializationIfNeeded() { return }
        if becameActive && !enrolling && disconnectAction == nil {
            if viewState.connection.failure != nil {
                centralManager.stopScan()
                viewState.connection = .waitingComputer
                if let target = viewState.target { recovery.allowRemembered(target.peripheralID) }
            } else if peripheral == nil && policy.requiresAdvertisement {
                centralManager.stopScan()
            }
            if let peripheral, peripheral.state == .connected {
                if policy.phase == .subscriptions { finishSubscriptions(peripheral) }
                else if policy.phase == .services && discoveryOperation == nil { discoverServices(peripheral) }
            }
            beginSearch(allowRememberedTarget: viewState.connection.failure == nil)
        }
    }

    private func beginSearch(allowRememberedTarget: Bool = true) {
        guard centralManager.state == .poweredOn else {
            viewState.connection = .bluetoothUnavailable
            publish()
            return
        }
        guard shouldConnect else {
            centralManager.stopScan()
            viewState.connection = viewState.target == nil ? .unregistered : .waitingComputer
            publish()
            return
        }
        if policy.phase != .ready && !centralManager.isScanning {
            recovery.beginScanRound()
            diagnostic("scan round=\(recovery.scanRound) started; service filter active")
            centralManager.scanForPeripherals(withServices: [Self.serviceUUID])
        }
        if peripheral == nil {
            policy.waitForComputer()
            if viewState.connection.failure == nil { viewState.connection = .waitingComputer }
        }
        reconcileConnections()
        if peripheral == nil && allowRememberedTarget && !policy.requiresAdvertisement && !rememberedTargetRejected && !enrolling,
           let target = viewState.target {
            if rememberedPeripheral == nil {
                rememberedPeripheral = centralManager.retrievePeripherals(withIdentifiers: [target.peripheralID]).first
            }
            if let rememberedPeripheral { requestConnection(rememberedPeripheral, source: .remembered) }
        }
        publish()
    }

    private func requestConnection(_ candidate: CBPeripheral, source: BluetoothConnectionRecovery.Source) {
        guard shouldConnect, policy.phase != .ready else { return }
        let id = candidate.identifier
        if let existing = recovery.attempts[id] {
            if existing.stage == .cancelling && source == .advertisement {
                deferredAdvertisements[id] = candidate
                diagnostic("advertisement retained until cancellation completes peripheralID=\(id) attempt=\(existing.generation)")
            } else { reconcileConnections() }
            return
        }
        guard let attempt = recovery.begin(id, source: source) else {
            diagnostic("connection candidate deferred or rejected peripheralID=\(id) source=\(source) pending=\(recovery.attempts.count)")
            return
        }
        beginConnection(candidate, attempt: attempt)
    }

    private func beginConnection(_ candidate: CBPeripheral, attempt: BluetoothConnectionRecovery.Attempt) {
        connectionPeripherals[candidate.identifier] = candidate
        candidate.delegate = self
        diagnostic("system connection waiting peripheralID=\(candidate.identifier) attempt=\(attempt.generation) nativeState=\(candidate.state.rawValue) retries=\(attempt.remainingRetries)")
        if candidate.state == .connected {
            _ = recovery.connected(candidate.identifier, generation: attempt.generation)
            activateNextConnection()
        } else { requestNativeConnection(candidate) }
        if peripheral == nil && viewState.connection.failure == nil {
            viewState.connection = candidate.identifier == viewState.target?.peripheralID ? .waitingComputer : .connecting
        }
        publish()
    }

    private func activateNextConnection() {
        let available = Set(connectionPeripherals.values.filter { $0.state == .connected }.map { $0.identifier })
        guard shouldConnect, centralManager.state == .poweredOn, peripheral == nil, disconnectAction == nil,
              let attempt = recovery.selectConnected(preferred: enrolling ? nil : viewState.target?.peripheralID,
                                                     available: available) else { return }
        guard let candidate = connectionPeripherals[attempt.peripheralID] else {
            diagnostic("connection registry missing peripheralID=\(attempt.peripheralID) attempt=\(attempt.generation)")
            _ = recovery.finish(attempt.peripheralID, generation: attempt.generation)
            viewState.connection = .failed("Bluetooth connection state is inconsistent. Retry the connection.")
            publish()
            return
        }
        peripheral = candidate
        policy.connected(now: now)
        clearCharacteristics()
        viewState.issue = nil
        diagnostic("connected; discovery starting peripheralID=\(candidate.identifier) attempt=\(attempt.generation) nativeState=\(candidate.state.rawValue)")
        startInitializationTimeout()
        discoverServices(candidate)
    }

    private func requestNativeConnection(_ candidate: CBPeripheral) {
        guard centralManager.state == .poweredOn, let attempt = recovery.attempts[candidate.identifier],
              recovery.request(candidate.identifier, generation: attempt.generation) else { return }
        if candidate.state == .disconnected {
            diagnostic("native connect requested peripheralID=\(candidate.identifier) attempt=\(attempt.generation)")
            centralManager.connect(candidate)
        }
    }

    private func reconcileConnections() {
        for candidate in Array(connectionPeripherals.values) {
            guard let attempt = recovery.attempts[candidate.identifier], attempt.stage == .waiting else { continue }
            if candidate.state == .connected { _ = recovery.connected(candidate.identifier, generation: attempt.generation) }
            else { requestNativeConnection(candidate) }
        }
        activateNextConnection()
    }

    func centralManagerDidUpdateState(_ central: CBCentralManager) {
        diagnostic("central state=\(central.state.rawValue)")
        guard central.state == .poweredOn else {
            central.stopScan()
            discardAuthentication(message: String(localized: "Bluetooth is unavailable. This request is no longer valid."))
            if enrolling {
                enrolling = false
                enrollmentSent = false
                viewState.enrollment = .failed(String(localized: "Bluetooth is unavailable. Pairing was not completed; the previous PC was kept."))
            }
            clearDisconnectedState()
            rememberedPeripheral = nil
            recovery.reset()
            connectionPeripherals.removeAll()
            deferredAdvertisements.removeAll()
            viewState.connection = .bluetoothUnavailable
            publish()
            return
        }
        _ = expireInitializationIfNeeded()
        beginSearch()
    }

    func centralManager(_ central: CBCentralManager, willRestoreState dict: [String: Any]) {
        diagnostic("restoration received")
        let restored = (dict[CBCentralManagerRestoredStatePeripheralsKey] as? [CBPeripheral] ?? []).sorted {
            ($0.identifier == viewState.target?.peripheralID ? 0 : 1) <
                ($1.identifier == viewState.target?.peripheralID ? 0 : 1)
        }
        for item in restored {
            guard shouldConnect, viewState.target != nil else {
                central.cancelPeripheralConnection(item)
                continue
            }
            if item.identifier == viewState.target?.peripheralID { rememberedPeripheral = item }
            diagnostic("restored peripheralID=\(item.identifier) nativeState=\(item.state.rawValue)")
            if recovery.attempts[item.identifier] == nil,
               let attempt = recovery.begin(item.identifier, source: .restoration) {
                beginConnection(item, attempt: attempt)
            } else if recovery.attempts[item.identifier] == nil {
                diagnostic("restored connection exceeds candidate limit; cancelling peripheralID=\(item.identifier)")
                central.cancelPeripheralConnection(item)
            }
        }
        if central.state == .poweredOn { beginSearch() }
    }

    func centralManager(_ central: CBCentralManager, didDiscover candidate: CBPeripheral,
                        advertisementData: [String: Any], rssi RSSI: NSNumber) {
        _ = expireInitializationIfNeeded()
        guard shouldConnect, policy.phase != .ready else { return }
        diagnostic("advertisement peripheralID=\(candidate.identifier) nativeState=\(candidate.state.rawValue) scanRound=\(recovery.scanRound)")
        requestConnection(candidate, source: .advertisement)
    }

    func centralManager(_ central: CBCentralManager, didConnect candidate: CBPeripheral) {
        _ = expireInitializationIfNeeded()
        if connectionPeripherals[candidate.identifier] === candidate,
           recovery.attempts[candidate.identifier]?.stage == .cancelling {
            diagnostic("late connect during cancellation ignored peripheralID=\(candidate.identifier)")
            return
        }
        guard connectionPeripherals[candidate.identifier] === candidate,
              let attempt = recovery.attempts[candidate.identifier], shouldConnect,
              attempt.stage != .cancelling else {
            diagnostic("unselected or cancelled connection callback peripheralID=\(candidate.identifier) nativeState=\(candidate.state.rawValue)")
            central.cancelPeripheralConnection(candidate)
            return
        }
        guard recovery.connected(candidate.identifier, generation: attempt.generation) else {
            diagnostic("connection callback already adopted peripheralID=\(candidate.identifier) attempt=\(attempt.generation)")
            return
        }
        diagnostic("native connected peripheralID=\(candidate.identifier) attempt=\(attempt.generation)")
        activateNextConnection()
    }

    func centralManager(_ central: CBCentralManager, didFailToConnect candidate: CBPeripheral, error: Error?) {
        if let error { diagnosticError("native connection peripheralID=\(candidate.identifier)", error) }
        connectionEnded(candidate, message: String(localized: "Could not establish a Bluetooth connection"), failedToConnect: true)
    }

    func centralManager(_ central: CBCentralManager, didDisconnectPeripheral candidate: CBPeripheral, error: Error?) {
        if let error { diagnosticError("native disconnect peripheralID=\(candidate.identifier)", error) }
        connectionEnded(candidate, message: String(localized: "Bluetooth disconnected"), failedToConnect: false)
    }

    private func connectionEnded(_ candidate: CBPeripheral, message: String, failedToConnect: Bool) {
        let id = candidate.identifier
        guard connectionPeripherals[id] === candidate, let attempt = recovery.attempts[id],
              let completed = recovery.finish(id, generation: attempt.generation) else {
            diagnostic("old connection end ignored peripheralID=\(id) nativeState=\(candidate.state.rawValue)")
            return
        }
        connectionPeripherals.removeValue(forKey: id)
        diagnostic("connection ended peripheralID=\(id) attempt=\(completed.generation) stage=\(completed.stage) nativeState=\(candidate.state.rawValue)")
        let wasActive = peripheral === candidate
        let action = wasActive ? disconnectAction : nil
        if wasActive {
            disconnectAction = nil
            discardAuthentication(message: String(localized: "Bluetooth disconnected. This authentication is no longer valid."))
            clearDisconnectedState()
            if action == nil && enrolling && enrollmentSent {
                enrolling = false
                enrollmentSent = false
                viewState.enrollment = .failed(String(localized: "The pairing connection was interrupted. The previous PC was kept."))
            }
        }
        if let action {
            resumeAfterDisconnect(action, candidate: candidate, completed: completed)
        } else if completed.stage != .cancelling {
            let retry = failedToConnect || completed.stage != .ready
            if retry { recovery.failed(id) }
            activateNextConnection()
            if shouldConnect && retry && policy.phase != .ready,
               let next = recovery.retry(completed) {
                beginConnection(candidate, attempt: next)
            } else if retry && peripheral == nil && shouldConnect {
                viewState.connection = .failed(String(localized: "\(message); waiting for PC advertising"))
                if enrolling {
                    enrolling = false
                    viewState.enrollment = .failed(String(localized: "\(message); the previous PC was kept"))
                }
            }
            beginSearch(allowRememberedTarget: !retry && !policy.requiresAdvertisement)
        } else if peripheral == nil { beginSearch() }
        if let advertised = deferredAdvertisements.removeValue(forKey: id) {
            requestConnection(advertised, source: .advertisement)
        }
        publish()
    }

    private func cancelOtherConnections() {
        for candidate in Array(connectionPeripherals.values) where candidate !== peripheral {
            cancelConnection(candidate)
        }
    }

    private func cancelConnection(_ candidate: CBPeripheral) {
        guard let attempt = recovery.attempts[candidate.identifier], recovery.cancel(candidate.identifier) else { return }
        diagnostic("connection cancellation peripheralID=\(candidate.identifier) nativeState=\(candidate.state.rawValue)")
        if candidate.state == .disconnected && !attempt.connectionRequested && attempt.stage == .waiting {
            connectionEnded(candidate, message: String(localized: "Connection cancelled"), failedToConnect: false)
        } else { centralManager.cancelPeripheralConnection(candidate) }
    }

    private func disconnect(action: DisconnectAction) {
        if action == .halt || action == .resume {
            centralManager.stopScan()
            deferredAdvertisements.removeAll()
            cancelOtherConnections()
        }
        discardAuthentication(message: String(localized: "The connection ended. This authentication is no longer valid."))
        if action != .halt { viewState.connection = .recovering }
        else { viewState.connection = viewState.target == nil ? .unregistered : .waitingComputer }
        guard let peripheral else { resumeAfterDisconnect(action); return }
        disconnectAction = action
        initializationTimeout?.cancel()
        initializationTimeout = nil
        clearCharacteristics()
        policy.failed()
        cancelConnection(peripheral)
    }

    private func resumeAfterDisconnect(_ action: DisconnectAction, candidate: CBPeripheral? = nil,
                                       completed: BluetoothConnectionRecovery.Attempt? = nil) {
        switch action {
        case .recover:
            activateNextConnection()
            if shouldConnect && policy.phase != .ready, let candidate, let completed,
               let attempt = recovery.retry(completed) { beginConnection(candidate, attempt: attempt) }
            beginSearch(allowRememberedTarget: false)
        case .search: beginSearch()
        case .resume:
            beginSearch()
        case .advertisement:
            viewState.connection = .waitingComputer
            beginSearch(allowRememberedTarget: false)
        case .halt:
            if shouldConnect { beginSearch(); return }
            viewState.connection = viewState.target == nil ? .unregistered : .waitingComputer
            publish()
        }
    }

    private func failConnection(_ message: String) {
        guard disconnectAction == nil else { return }
        let stage = String(describing: policy.phase)
        let failure = String(localized: "\(message) (stage: \(stage)); waiting for the PC to recover")
        let elapsed = policy.deadline.map { max(0, now - ($0 - BluetoothAuthenticationState.initializationLifetime)) }
        let retries = peripheral.flatMap { recovery.attempts[$0.identifier]?.remainingRetries } ?? 0
        diagnostic("initialization or transport failed phase=\(stage) elapsed=\(elapsed ?? 0) retryRemaining=\(retries)")
        viewState.issue = nil
        discardAuthentication(message: message)
        if enrolling && enrollmentSent {
            enrolling = false
            enrollmentSent = false
            viewState.enrollment = .failed(String(localized: "\(message); pairing was not confirmed and the previous PC was kept"))
        }
        let retry = shouldConnect && retries > 0
        if retry {
            viewState.connection = .recovering
            disconnect(action: .recover)
        } else {
            if enrolling { enrolling = false; viewState.enrollment = .failed(message) }
            if let peripheral { recovery.failed(peripheral.identifier) }
            disconnect(action: .search)
            viewState.connection = .failed(failure)
        }
        publish()
    }

    private func rejectCandidate(_ message: String) {
        diagnostic("candidate rejected during identity verification")
        if let peripheral { recovery.reject(peripheral.identifier) }
        if let peripheral, peripheral === rememberedPeripheral || peripheral.identifier == viewState.target?.peripheralID {
            rememberedTargetRejected = true
            rememberedPeripheral = nil
        }
        viewState.issue = message
        if enrolling {
            enrolling = false
            enrollmentSent = false
            viewState.enrollment = .failed(String(localized: "\(message); the previous PC was kept"))
            viewState.connection = .failed(message)
            disconnect(action: .halt)
        } else { disconnect(action: .search) }
        publish()
    }

    private func waitForService() {
        diagnostic("service absent; releasing connection and waiting for advertisement")
        discardAuthentication(message: String(localized: "The unlock service is unavailable. This authentication is no longer valid."))
        if enrolling {
            enrolling = false
            enrollmentSent = false
            viewState.enrollment = .failed(String(localized: "The pairing service was not found. Open Pair iPhone on Windows; the previous PC was kept."))
        }
        initializationTimeout?.cancel()
        initializationTimeout = nil
        clearCharacteristics()
        serviceInDiscovery = nil
        identityReadInDiscovery = nil
        let newAvailabilityRound = !policy.requiresAdvertisement
        policy.serviceMissing()
        viewState.issue = nil
        if newAvailabilityRound {
            centralManager.stopScan()
        }
        deferredAdvertisements.removeAll()
        cancelOtherConnections()
        if shouldConnect { disconnect(action: .advertisement) }
        else { disconnect(action: .halt) }
        publish()
    }

    private func rediscoverServices(_ peripheral: CBPeripheral, trigger: String) {
        guard !expireInitializationIfNeeded() else { return }
        diagnostic("service recovery trigger=\(trigger) pending=\(discoveryOperation != nil)")
        discardAuthentication(message: String(localized: "The service changed. Authentication was cancelled; start a new request on Windows."))
        clearCharacteristics()
        viewState.issue = nil
        recovery.restartInitialization(peripheral.identifier)
        let discover = policy.invalidateServices(now: now, discoveryPending: discoveryOperation != nil)
        viewState.connection = .recovering
        startInitializationTimeout()
        if discover { discoverServices(peripheral) }
        publish()
    }

    private func startInitializationTimeout() {
        initializationTimeout?.cancel()
        guard let deadline = policy.deadline, let current = peripheral else { return }
        let generation = policy.generation
        initializationTimeout = Task { [weak self] in
            do { try await Task.sleep(for: .seconds(max(0, deadline - ProcessInfo.processInfo.systemUptime))) }
            catch { return }
            guard let self, self.peripheral === current, self.policy.generation == generation,
                  self.policy.deadline == deadline else { return }
            _ = self.expireInitializationIfNeeded()
        }
    }

    @discardableResult
    private func expireInitializationIfNeeded() -> Bool {
        guard peripheral != nil, disconnectAction == nil, policy.initializationExpired(now: now) else { return false }
        failConnection(String(localized: "Service initialization exceeded 10 seconds after connecting."))
        return true
    }

    private func discoverServices(_ peripheral: CBPeripheral) {
        guard discoveryOperation == nil else { return }
        viewState.connection = viewState.connection == .recovering ? .recovering : .discovering
        discoveryOperation = .services
        diagnostic("service discovery deadlineRemaining=\(max(0, (policy.deadline ?? now) - now))")
        peripheral.discoverServices([Self.serviceUUID])
        publish()
    }

    private func advanceDiscovery(_ peripheral: CBPeripheral) -> Bool {
        guard policy.deadline != nil else {
            diagnostic("late discovery callback drained during passive wait")
            return false
        }
        switch policy.completeDiscoveryStep(now: now) {
        case .proceed: return true
        case .rediscover:
            serviceInDiscovery = nil
            identityReadInDiscovery = nil
            discoverServices(peripheral)
            return false
        case .expired:
            failConnection(String(localized: "Service recovery exceeded 10 seconds."))
            return false
        }
    }

    func peripheral(_ peripheral: CBPeripheral, didDiscoverServices error: Error?) {
        guard self.peripheral === peripheral, discoveryOperation == .services else { return }
        discoveryOperation = nil
        guard advanceDiscovery(peripheral) else { return }
        if let error { diagnosticError("service discovery", error); failConnection("Service discovery failed: \(error.localizedDescription)"); return }
        guard let service = peripheral.services?.first(where: { $0.uuid == Self.serviceUUID }) else {
            waitForService()
            return
        }
        serviceInDiscovery = service
        policy.discoveredServices()
        discoveryOperation = .characteristics
        peripheral.discoverCharacteristics([Self.requestCharacteristicUUID, Self.challengeCharacteristicUUID,
            Self.assertionCharacteristicUUID, Self.resultCharacteristicUUID, Self.computerIDCharacteristicUUID], for: service)
    }

    func peripheral(_ peripheral: CBPeripheral, didDiscoverCharacteristicsFor service: CBService, error: Error?) {
        guard self.peripheral === peripheral, service === serviceInDiscovery,
              discoveryOperation == .characteristics else { return }
        discoveryOperation = nil
        guard advanceDiscovery(peripheral) else { return }
        if let error { diagnosticError("characteristic discovery", error); failConnection("Characteristic discovery failed: \(error.localizedDescription)"); return }
        guard let chars = service.characteristics,
              let request = chars.first(where: { $0.uuid == Self.requestCharacteristicUUID }),
              let challenge = chars.first(where: { $0.uuid == Self.challengeCharacteristicUUID }),
              let assertion = chars.first(where: { $0.uuid == Self.assertionCharacteristicUUID }),
              let result = chars.first(where: { $0.uuid == Self.resultCharacteristicUUID }) else {
            failConnection(String(localized: "The Windows unlock service is missing required characteristics."))
            return
        }
        guard let identity = chars.first(where: { $0.uuid == Self.computerIDCharacteristicUUID }),
              identity.properties.contains(.read) else {
            rejectCandidate(String(localized: "Windows does not provide a stable Computer ID. Update the Windows components."))
            return
        }
        requestCharacteristic = request
        challengeCharacteristic = challenge
        assertionCharacteristic = assertion
        resultCharacteristic = result
        identityReadInDiscovery = identity
        policy.discoveredCharacteristics()
        discoveryOperation = .identity
        viewState.connection = .verifyingComputer
        peripheral.readValue(for: identity)
        publish()
    }

    func peripheral(_ peripheral: CBPeripheral, didUpdateNotificationStateFor characteristic: CBCharacteristic, error: Error?) {
        guard self.peripheral === peripheral,
              characteristic === challengeCharacteristic || characteristic === resultCharacteristic else { return }
        guard policy.phase == .subscriptions || policy.phase == .ready else { return }
        if let error { diagnosticError("notification subscription", error); failConnection("Notification subscription failed: \(error.localizedDescription)"); return }
        guard characteristic.isNotifying else { failConnection(String(localized: "Windows notification subscriptions are no longer valid.")); return }
        finishSubscriptions(peripheral)
    }

    private func finishSubscriptions(_ peripheral: CBPeripheral) {
        guard disconnectAction == nil, !expireInitializationIfNeeded() else { return }
        let challenge = challengeCharacteristic?.isNotifying == true
        let result = resultCharacteristic?.isNotifying == true
        diagnostic("subscriptions challenge=\(challenge) result=\(result)")
        guard policy.subscriptions(challenge: challenge, result: result, now: now) else { return }
        initializationTimeout?.cancel()
        initializationTimeout = nil
        centralManager.stopScan()
        recovery.ready(peripheral.identifier)
        deferredAdvertisements.removeAll()
        cancelOtherConnections()
        viewState.connection = .ready
        viewState.issue = nil
        diagnostic("ready; computer identity verified")
        if enrolling { sendEnrollment(peripheral) }
        else if var target = viewState.target {
            target.peripheralID = peripheral.identifier
            saveTarget(target)
            sendReadyAcknowledgment(peripheral)
        }
        publish()
    }

    private func sendEnrollment(_ peripheral: CBPeripheral) {
        guard !enrollmentSent, let requestCharacteristic, policy.verifiedComputerID != nil else { return }
        do {
            let key = try keyStore.publicKeyRawRepresentation()
            guard key.count == 65 else { throw UnlockError.protocolEncodingFailed(String(localized: "Invalid public key length")) }
            var request = Data([0x02])
            request.append(key)
            enrollmentSent = true
            viewState.enrollment = .waitingConfirmation
            guard write(request, to: requestCharacteristic, purpose: .enrollment(enrollmentSequence)) else { return }
            diagnostic("enrollment sent; waiting Windows confirmation")
        } catch {
            enrolling = false
            viewState.enrollment = .failed(String(localized: "Could not submit pairing: \(error.localizedDescription)"))
        }
    }

    private func saveTarget(_ target: RegisteredComputer) {
        do {
            let data = try JSONEncoder().encode(target)
            defaults.set(data, forKey: RegisteredComputer.storageKey)
            viewState.target = target
        } catch {
            viewState.issue = String(localized: "Could not save PC information: \(error.localizedDescription)")
            if enrolling { viewState.enrollment = .failed(String(localized: "PC information was not saved. The previous PC was kept.")) }
        }
    }

    func peripheral(_ peripheral: CBPeripheral, didUpdateValueFor characteristic: CBCharacteristic, error: Error?) {
        guard self.peripheral === peripheral else { return }
        guard disconnectAction == nil, !expireInitializationIfNeeded() else { return }
        if characteristic === identityReadInDiscovery && discoveryOperation == .identity {
            discoveryOperation = nil
            guard advanceDiscovery(peripheral) else { return }
            if let error { diagnosticError("computer identity read", error) }
            guard error == nil, let data = characteristic.value,
                  let id = BluetoothAuthenticationState.computerID(from: data) else {
                rejectCandidate(String(localized: "Windows Computer ID is missing or invalid."))
                return
            }
            guard policy.verifyComputer(id, expected: viewState.target?.computerID, enrolling: enrolling, now: now) else {
                diagnostic("candidate identity mismatch")
                rejectCandidate(String(localized: "This is not the paired PC. No signature was sent."))
                return
            }
            if !enrolling {
                rememberedPeripheral = peripheral
                rememberedTargetRejected = false
            }
            let name = peripheral.name?.trimmingCharacters(in: .whitespacesAndNewlines) ?? ""
            viewState.connectedComputer = RegisteredComputer(computerID: id,
                name: name.isEmpty ? String(localized: "Windows PC") : name, peripheralID: peripheral.identifier)
            identityReadInDiscovery = nil
            viewState.connection = .subscribing
            if let challengeCharacteristic, !challengeCharacteristic.isNotifying {
                peripheral.setNotifyValue(true, for: challengeCharacteristic)
            }
            if let resultCharacteristic, !resultCharacteristic.isNotifying {
                peripheral.setNotifyValue(true, for: resultCharacteristic)
            }
            finishSubscriptions(peripheral)
            publish()
            return
        }
        guard disconnectAction == nil else {
            diagnostic("notification discarded during connection cancellation")
            return
        }
        if characteristic.uuid == Self.resultCharacteristicUUID, error == nil,
           characteristic === resultCharacteristic,
           let data = characteristic.value,
           let result = try? JSONDecoder().decode(WindowsResult.self, from: data),
           result.status == "transport_ready_required" {
            guard !result.authenticated, let id = result.requestID, !enrolling else {
                diagnostic("invalid or stale ready probe rejected")
                return
            }
            if id == lastHandledRequest {
                diagnostic("ready probe for handled challenge ignored")
                return
            }
            guard pendingChallenge == nil, awaitingResultID == nil,
                  policy.cacheReadyProbe(id, generation: policy.generation, now: now) else {
                diagnostic("stale or overlapping ready probe rejected")
                return
            }
            history.begin(id)
            diagnostic("ready probe received requestID=\(id.uuidString.lowercased()) phase=\(policy.phase)")
            sendReadyAcknowledgment(peripheral)
            return
        }
        if characteristic === resultCharacteristic, error == nil, policy.phase != .ready,
           let data = characteristic.value,
           let result = try? JSONDecoder().decode(WindowsResult.self, from: data),
           !result.authenticated, result.requestID != nil, result.requestID == policy.readyProbe?.requestID {
            handleWindowsResult(data, peripheral: peripheral)
            return
        }
        guard characteristic === resultCharacteristic || characteristic === challengeCharacteristic else {
            if characteristic.uuid == Self.resultCharacteristicUUID || characteristic.uuid == Self.challengeCharacteristicUUID {
                diagnostic("notification from an old characteristic ignored")
            }
            return
        }
        if let error { diagnosticError("notification", error); failConnection("Bluetooth notification failed: \(error.localizedDescription)"); return }
        guard policy.phase == .ready,
              characteristic === resultCharacteristic || characteristic === challengeCharacteristic else {
            diagnostic("notification before Ready ignored; challenge was not accepted")
            return
        }
        guard let data = characteristic.value else { failConnection(String(localized: "Windows notification contains no data.")); return }
        if characteristic === resultCharacteristic { handleWindowsResult(data, peripheral: peripheral) }
        else { handleChallenge(data, peripheral: peripheral) }
    }

    private struct WindowsResult: Decodable {
        let authenticated: Bool
        let status: String
        let detail: String?
        let requestID: UUID?
    }

    private func sendReadyAcknowledgment(_ peripheral: CBPeripheral) {
        guard self.peripheral === peripheral, disconnectAction == nil,
              policy.acceptsAuthentication(target: viewState.target?.computerID,
                  enrolling: enrolling),
              let requestCharacteristic, challengeCharacteristic?.isNotifying == true,
              resultCharacteristic?.isNotifying == true,
              let id = policy.beginReadyAcknowledgment(now: now) else { return }
        var frame = Data([0x04])
        frame.append(Data(id.uuidString.lowercased().utf8))
        if write(frame, to: requestCharacteristic, purpose: .readyAcknowledgment(id)) {
            diagnostic("ready acknowledgment sent requestID=\(id.uuidString.lowercased())")
        } else {
            policy.clearReadyProbe()
            diagnostic("ready acknowledgment could not be written")
        }
    }

    private func handleWindowsResult(_ data: Data, peripheral: CBPeripheral) {
        do {
            let result = try JSONDecoder().decode(WindowsResult.self, from: data)
            if let outcome = BluetoothAuthenticationState.enrollmentOutcome(code: result.status, detail: result.detail) {
                guard enrolling, enrollmentSent, let id = policy.verifiedComputerID else { return }
                diagnostic("Windows enrollment result=\(allowedResult(result.status)) reloadFailed=\(result.detail == "saved_reload_failed")")
                let name = peripheral.name?.trimmingCharacters(in: .whitespacesAndNewlines) ?? ""
                let candidate = RegisteredComputer(computerID: id,
                    name: name.isEmpty ? String(localized: "Paired Windows PC") : name, peripheralID: peripheral.identifier)
                if let target = viewState.completeEnrollment(outcome, candidate: candidate) {
                    saveTarget(target)
                    if viewState.target == target {
                        rememberedPeripheral = peripheral
                        rememberedTargetRejected = false
                    }
                }
                enrolling = false
                enrollmentSent = false
                if outcome != .succeeded { disconnect(action: .resume) }
                publish()
                return
            }
            if result.status.hasPrefix("enrollment_") {
                if enrolling && enrollmentSent {
                    enrolling = false
                    enrollmentSent = false
                    viewState.enrollment = .failed(String(localized: "Windows returned an unknown pairing result. The previous PC was not changed."))
                    disconnect(action: .resume)
                    publish()
                }
                diagnostic("unknown or stale enrollment result ignored")
                return
            }
            if result.requestID == nil && (pendingChallenge != nil || awaitingResultID != nil || policy.readyProbe != nil) {
                history.complete(pendingChallenge?.requestID ?? awaitingResultID ?? policy.readyProbe?.requestID, approved: false, at: Date())
                finishPending()
                viewState.authentication = .rejected(String(localized: "The Windows authentication result has no request ID. Start a new request."))
                diagnostic("authentication result missing request association")
                publish()
                return
            }
            guard BluetoothAuthenticationState.acceptsResult(requestID: result.requestID,
                pending: pendingChallenge?.requestID ?? policy.readyProbe?.requestID, awaiting: awaitingResultID) else { return }
            if result.requestID == policy.readyProbe?.requestID &&
                (result.authenticated || result.status == "unlock_approved") {
                diagnostic("approval result during preparation ignored")
                return
            }
            diagnostic("Windows authentication result=\(allowedResult(result.status)) authenticated=\(result.authenticated)")
            history.complete(result.requestID, approved: result.authenticated && result.status == "unlock_approved", at: Date())
            finishPending()
            if result.authenticated && result.status == "unlock_approved" {
                viewState.authentication = .approved
            } else {
                viewState.authentication = .rejected(authenticationFailureText(result.status))
            }
            publish()
        } catch {
            history.complete(pendingChallenge?.requestID ?? awaitingResultID ?? policy.readyProbe?.requestID, approved: false, at: Date())
            viewState.issue = String(localized: "Windows returned an invalid result format.")
            diagnostic("Windows result decoding failed")
            publish()
        }
    }

    private func handleChallenge(_ data: Data, peripheral: CBPeripheral) {
        do {
            let challenge = try UnlockProtocol.decodeChallenge(from: data)
            guard challenge.requestID != lastHandledRequest else { return }
            guard policy.acceptsPreparedChallenge(challenge.requestID, now: now) else {
                diagnostic("challenge without current ready acknowledgment rejected requestID=\(challenge.requestID.uuidString.lowercased())")
                return
            }
            policy.clearReadyProbe()
            if pendingChallenge != nil { rejectPending(reason: 6, message: String(localized: "A new request replaced the previous request.")) }
            finishPending()
            history.begin(challenge.requestID)
            pendingChallenge = challenge
            pendingDeadline = now + BluetoothAuthenticationState.responseLifetime
            lastHandledRequest = challenge.requestID
            guard challenge.version == 1, challenge.audience == "windows-unlock", challenge.nonce.count == 32 else {
                rejectPending(reason: 6, message: String(localized: "Invalid Windows request format."))
                return
            }
            guard policy.acceptsAuthentication(target: viewState.target?.computerID,
                enrolling: enrolling) else {
                rejectPending(reason: 2, message: String(localized: "The PC is not paired or pairing is in progress."))
                return
            }
            viewState.authentication = .readingRSSI
            diagnostic("challenge received requestID=\(challenge.requestID.uuidString.lowercased()) foreground=\(foreground); fresh RSSI required")
            let id = challenge.requestID
            authenticationTimeout = Task { [weak self] in
                do { try await Task.sleep(for: .seconds(BluetoothAuthenticationState.responseLifetime)) }
                catch { return }
                guard let self, self.pendingChallenge?.requestID == id else { return }
                self.rejectPending(reason: 3, message: String(localized: "Signal reading and signing exceeded 3 seconds."))
            }
            readChallengeRSSI(peripheral)
            publish()
        } catch {
            history.complete(pendingChallenge?.requestID ?? awaitingResultID ?? policy.readyProbe?.requestID, approved: false, at: Date())
            viewState.authentication = .rejected(String(localized: "Invalid Windows challenge format."))
            diagnostic("challenge decoding failed")
            publish()
        }
    }

    private func readChallengeRSSI(_ peripheral: CBPeripheral) {
        guard let challenge = pendingChallenge else { return }
        guard now < pendingDeadline else {
            rejectPending(reason: 3, message: String(localized: "This signal reading expired."))
            return
        }
        guard
              let read = policy.beginRSSI(requestID: challenge.requestID, now: now) else { return }
        rssiTimeout?.cancel()
        rssiTimeout = Task { [weak self] in
            do { try await Task.sleep(for: .seconds(BluetoothAuthenticationState.responseLifetime)) }
            catch { return }
            guard let self, self.peripheral === peripheral,
                  self.policy.rssiRead?.sequence == read.sequence else { return }
            self.diagnostic("RSSI callback missing; bounded connection recovery")
            if self.pendingChallenge?.requestID == read.requestID {
                self.rejectPending(reason: 3, message: String(localized: "No signal reading was received for this request."))
            }
            self.failConnection(String(localized: "The signal reading timed out. The connection needs recovery."))
        }
        peripheral.readRSSI()
    }

    func peripheral(_ peripheral: CBPeripheral, didReadRSSI RSSI: NSNumber, error: Error?) {
        guard self.peripheral === peripheral, policy.rssiRead != nil else { return }
        let read = policy.finishRSSI(now: now, requestID: pendingChallenge?.requestID)
        rssiTimeout?.cancel()
        rssiTimeout = nil
        guard let read, let challenge = pendingChallenge, read.requestID == challenge.requestID else {
            diagnostic("stale RSSI callback discarded")
            if pendingChallenge != nil { readChallengeRSSI(peripheral) }
            return
        }
        let value = RSSI.intValue
        if error != nil {
            rejectPending(reason: 3, message: String(localized: "Could not read the signal for this request."))
            return
        }
        let decision = BluetoothAuthenticationState.signalDecision(rssi: value, threshold: viewState.threshold,
            now: now, deadline: pendingDeadline)
        guard decision != .invalid else { rejectPending(reason: 3, message: String(localized: "Invalid signal reading for this request.")); return }
        guard decision != .expired else { rejectPending(reason: 3, message: String(localized: "This signal reading expired.")); return }
        history.measured(value, for: challenge.requestID)
        viewState.rssi = value
        viewState.rssiMeasuredAt = Date()
        diagnostic("fresh RSSI=\(value) threshold=\(viewState.threshold)")
        guard decision == .approve else {
            rejectPending(reason: 1, message: String(localized: "Move closer to your PC and try again."))
            return
        }
        guard policy.acceptsAuthentication(target: viewState.target?.computerID,
            enrolling: enrolling), let assertionCharacteristic else {
            rejectPending(reason: 2, message: String(localized: "This connection is not eligible to approve requests."))
            return
        }
        do {
            viewState.authentication = .signing
            publish()
            let assertion = try UnlockProtocol.sign(challenge: challenge, using: keyStore)
            let data = try UnlockProtocol.encode(assertion: assertion)
            guard now < pendingDeadline else {
                rejectPending(reason: 6, message: String(localized: "This request expired before signing completed."))
                return
            }
            guard write(data, to: assertionCharacteristic, purpose: .assertion(challenge.requestID)) else { return }
            awaitingResultID = challenge.requestID
            pendingChallenge = nil
            authenticationTimeout?.cancel()
            authenticationTimeout = nil
            viewState.authentication = .awaitingWindows
            diagnostic("assertion sent; awaiting Windows result")
            publish()
        } catch { rejectPending(reason: 6, message: String(localized: "Signing failed: \(error.localizedDescription)")) }
    }

    private func write(_ data: Data, to characteristic: CBCharacteristic, purpose: WritePurpose) -> Bool {
        guard let peripheral, peripheral.state == .connected, policy.phase == .ready else { return false }
        guard writes.values.reduce(0, { $0 + $1.count }) < 16 else {
            failConnection(String(localized: "Previous Bluetooth writes are unconfirmed. The connection needs recovery."))
            return false
        }
        writes[ObjectIdentifier(characteristic), default: []].append(
            WriteContext(characteristic: characteristic, generation: policy.generation, purpose: purpose))
        peripheral.writeValue(data, for: characteristic, type: .withResponse)
        return true
    }

    func peripheral(_ peripheral: CBPeripheral, didWriteValueFor characteristic: CBCharacteristic, error: Error?) {
        guard self.peripheral === peripheral else { return }
        let key = ObjectIdentifier(characteristic)
        guard var queue = writes[key], !queue.isEmpty else { return }
        let context = queue.removeFirst()
        if queue.isEmpty { writes.removeValue(forKey: key) } else { writes[key] = queue }
        guard policy.phase == .ready, policy.isCurrentGeneration(context.generation) else {
            diagnostic("stale write callback drained")
            return
        }
        if case let .readyAcknowledgment(id) = context.purpose {
            guard policy.readyProbe?.requestID == id else {
                diagnostic("ready acknowledgment callback for ended preparation ignored")
                return
            }
            policy.finishReadyAcknowledgment(id, generation: context.generation)
            if let error {
                diagnosticError("ready acknowledgment write", error)
                diagnostic("ready acknowledgment write failed requestID=\(id.uuidString.lowercased()) code=\((error as NSError).code)")
                failConnection(String(localized: "Could not send the unlock channel readiness acknowledgment."))
            }
            return
        }
        guard error != nil else { return }
        switch context.purpose {
        case let .assertion(id):
            guard id == awaitingResultID, characteristic === assertionCharacteristic else { return }
            if let requestCharacteristic {
                var reject = Data([0x03])
                reject.append(Data(id.uuidString.lowercased().utf8))
                reject.append(6)
                _ = write(reject, to: requestCharacteristic, purpose: .rejection(id))
            }
            history.complete(awaitingResultID, approved: false, at: Date())
            finishPending()
            viewState.authentication = .rejected(String(localized: "Could not send the signature. Start a new request on Windows."))
        case let .enrollment(sequence):
            guard enrolling, enrollmentSent, sequence == enrollmentSequence else { return }
            enrolling = false
            enrollmentSent = false
            viewState.enrollment = .failed(String(localized: "Could not send the pairing request. The previous PC was kept."))
            disconnect(action: .resume)
        case let .rejection(id):
            guard id == awaitingResultID else { return }
            viewState.issue = String(localized: "Could not deliver the iPhone rejection to Windows.")
        case .readyAcknowledgment: return
        }
        diagnostic("BLE write failed for current operation")
        publish()
    }

    func peripheral(_ peripheral: CBPeripheral, didModifyServices invalidatedServices: [CBService]) {
        guard self.peripheral === peripheral, peripheral.state == .connected,
              disconnectAction == nil,
              invalidatedServices.contains(where: { $0.uuid == Self.serviceUUID }) else { return }
        diagnostic("GATT service invalidated; rediscovering without forced disconnect")
        discardAuthentication(message: String(localized: "The service changed. Authentication was cancelled; start a new request on Windows."))
        if enrolling && enrollmentSent {
            enrolling = false
            enrollmentSent = false
            viewState.enrollment = .failed(String(localized: "The service changed during pairing. The result is unconfirmed; the previous PC was kept."))
        }
        rediscoverServices(peripheral, trigger: "GATT service change")
    }

    private func rejectPending(reason: UInt8, message: String) {
        guard let challenge = pendingChallenge else { return }
        history.complete(challenge.requestID, approved: false, at: Date())
        if let peripheral, peripheral.state == .connected, policy.phase == .ready, let requestCharacteristic {
            var data = Data([0x03])
            data.append(Data(challenge.requestID.uuidString.lowercased().utf8))
            data.append(reason)
            guard write(data, to: requestCharacteristic, purpose: .rejection(challenge.requestID)) else { return }
            awaitingResultID = challenge.requestID
        }
        pendingChallenge = nil
        authenticationTimeout?.cancel()
        authenticationTimeout = nil
        viewState.authentication = .rejected(message)
        diagnostic("approval rejected reason=\(reason)")
        publish()
    }

    private func finishPending() {
        policy.clearReadyProbe()
        pendingChallenge = nil
        awaitingResultID = nil
        authenticationTimeout?.cancel()
        authenticationTimeout = nil
    }

    private func discardAuthentication(message: String) {
        history.complete(pendingChallenge?.requestID ?? awaitingResultID ?? policy.readyProbe?.requestID, approved: false, at: Date())
        policy.clearReadyProbe()
        if pendingChallenge != nil || awaitingResultID != nil {
            viewState.authentication = .rejected(message)
        }
        else { viewState.authentication = .waiting }
        finishPending()
    }

    private func clearCharacteristics() {
        policy.clearReadyProbe()
        viewState.connectedComputer = nil
        requestCharacteristic = nil
        challengeCharacteristic = nil
        assertionCharacteristic = nil
        resultCharacteristic = nil
    }

    private func clearDisconnectedState() {
        disconnectAction = nil
        writes.removeAll()
        initializationTimeout?.cancel()
        initializationTimeout = nil
        rssiTimeout?.cancel()
        rssiTimeout = nil
        clearCharacteristics()
        discoveryOperation = nil
        serviceInDiscovery = nil
        identityReadInDiscovery = nil
        policy.disconnected()
        peripheral = nil
    }

    private func publish() {
        viewState.lastResult = history.result
        if history.result != persistedResult {
            do {
                try history.save(to: defaults)
                persistedResult = history.result
            } catch { viewState.issue = String(localized: "Request history could not be saved: \(error.localizedDescription)") }
        }
        onUpdate?(viewState)
    }

    private func diagnostic(_ event: String) {
        let request = pendingChallenge?.requestID ?? awaitingResultID ?? policy.readyProbe?.requestID
        let attempt = peripheral.flatMap { recovery.attempts[$0.identifier] }
        let text = "\(diagnosticClock.string(from: Date())) uptimeMs=\(Int(now * 1000)) generation=\(policy.generation) requestID=\(request?.uuidString.lowercased() ?? "none") peripheralID=\(peripheral?.identifier.uuidString.lowercased() ?? "none") attempt=\(attempt?.generation ?? 0) nativeState=\(peripheral?.state.rawValue ?? -1) \(event)"
        logger.info("\(text, privacy: .public)")
        onDiagnostic?(text)
    }

    private func diagnosticError(_ operation: String, _ error: Error) {
        let native = error as NSError
        diagnostic("\(operation) failed domain=\(native.domain) code=\(native.code) detail=\(native.localizedDescription)")
    }

    private func allowedResult(_ code: String) -> String {
        let allowed = ["enrollment_saved", "enrollment_already_registered", "enrollment_cancelled",
            "enrollment_rejected", "enrollment_busy", "enrollment_expired", "enrollment_error", "enrollment_removed",
            "unlock_approved", "challenge_expired", "session_changed", "phone_rejected", "not_ready",
            "rssi_too_low", "automatic_disabled", "rssi_unavailable", "signing_failed", "transport_failed",
            "malformed_json", "unsupported_version", "invalid_request_id", "request_mismatch", "challenge_replayed",
            "key_not_enrolled", "invalid_key_id", "invalid_public_key", "key_id_mismatch", "invalid_signature_encoding",
            "invalid_signature", "cryptographic_api_failure", "service_error", "service_unavailable"]
        return allowed.contains(code) ? code : "unknown_result"
    }

    private func authenticationFailureText(_ code: String) -> String {
        switch code {
        case "challenge_expired": String(localized: "Windows authentication timed out. Press Enter again.")
        case "session_changed": String(localized: "The Windows session changed. Start a new request.")
        case "phone_rejected": String(localized: viewState.authentication.title)
        case "rssi_too_low": String(localized: "Move closer to your PC and try again.")
        case "automatic_disabled": String(localized: "Windows reported that automatic authentication is unavailable.")
        case "rssi_unavailable": String(localized: "Signal strength is unavailable. Try again.")
        case "signing_failed": String(localized: "Authentication was not completed. Try again.")
        case "transport_failed": String(localized: "There is a connection problem with your PC. Try again.")
        case "service_error", "service_unavailable": String(localized: "The Windows authentication service is unavailable.")
        case "not_ready": String(localized: "Windows is not ready to unlock.")
        default: String(localized: "Windows rejected authentication: \(allowedResult(code))")
        }
    }
}
