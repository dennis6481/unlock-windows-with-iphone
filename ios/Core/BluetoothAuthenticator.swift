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
    private var policy = BluetoothAuthenticationState()
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
    private enum WritePurpose { case enrollment(UInt64), assertion(UUID), rejection(UUID) }
    private struct WriteContext {
        let characteristic: CBCharacteristic
        let generation: UInt64
        let purpose: WritePurpose
    }
    private var writes: [ObjectIdentifier: [WriteContext]] = [:]
    private var foreground = false
    private var candidates: [CBPeripheral] = []
    private var retryCandidate: CBPeripheral?
    private var pendingChallenge: UnlockChallenge?
    private var pendingDeadline = 0.0
    private var awaitingResultID: UUID?
    private var lastHandledRequest: UUID?
    private var initializationTimeout: Task<Void, Never>?
    private var authenticationTimeout: Task<Void, Never>?
    private var rssiTimeout: Task<Void, Never>?
    private enum DisconnectAction: Equatable { case recover, search, resume, halt }
    private var disconnectAction: DisconnectAction?

    private var shouldConnect: Bool {
        enrolling || (viewState.automaticEnabled && viewState.target != nil)
    }
    private var now: TimeInterval { ProcessInfo.processInfo.systemUptime }

    init(keyStore: SecureEnclaveKeyStore = SecureEnclaveKeyStore(), defaults: UserDefaults = .standard) {
        self.keyStore = keyStore
        self.defaults = defaults
        super.init()
        viewState.automaticEnabled = BluetoothAuthenticationState.automaticPreference(defaults)
        viewState.threshold = defaults.object(forKey: "unlockRSSIThreshold") as? Int ?? -60
        if let data = defaults.data(forKey: "registeredWindowsComputer") {
            do { viewState.target = try JSONDecoder().decode(RegisteredComputer.self, from: data) }
            catch { viewState.issue = "保存的电脑信息无法读取，请明确重新登记电脑" }
        } else if defaults.string(forKey: "unlockTargetPeripheral") != nil {
            viewState.issue = "旧版只保存蓝牙 UUID，请重新登记一次以启用稳定电脑识别；手机密钥不变"
        }
        viewState.authentication = viewState.automaticEnabled ? .waiting : .paused
    }

    func activate() { publish(); _ = centralManager }

    func setAutomaticEnabled(_ enabled: Bool) {
        viewState.automaticEnabled = enabled
        defaults.set(enabled, forKey: "automaticUnlockEnabled")
        if !enabled {
            rejectPending(reason: 2, message: "自动响应已暂停")
            viewState.authentication = .paused
            if !enrolling { disconnect(action: .halt) }
        } else {
            viewState.authentication = .waiting
            retryConnection()
        }
        publish()
    }

    func setThreshold(_ value: Int) {
        viewState.threshold = min(-30, max(-100, value))
        defaults.set(viewState.threshold, forKey: "unlockRSSIThreshold")
        publish()
    }

    func retryConnection() {
        guard !enrolling else { return }
        guard disconnectAction == nil else {
            viewState.issue = "正在结束当前连接，请等待断连完成"
            publish()
            return
        }
        policy.resetConnectionRetries()
        rememberedTargetRejected = false
        centralManager.stopScan()
        candidates.removeAll()
        guard viewState.target != nil else {
            viewState.connection = .unregistered
            publish()
            return
        }
        viewState.issue = nil
        if let peripheral, peripheral.state == .connected, policy.phase == .ready { publish(); return }
        if peripheral != nil { disconnect(action: .resume) }
        else { beginSearch() }
    }

    func startEnrollment() {
        guard !viewState.enrollment.isActive else { return }
        guard disconnectAction == nil else {
            viewState.issue = "正在结束当前连接，请稍后开始登记"
            publish()
            return
        }
        discardAuthentication(message: "登记开始，本次认证已取消")
        enrolling = true
        enrollmentSent = false
        enrollmentSequence &+= 1
        policy.resetConnectionRetries()
        candidates.removeAll()
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
        if becameActive && !enrolling && disconnectAction == nil {
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
            policy.beginScanRound()
            if let peripheral, peripheral.state != .connected { _ = policy.discoverCandidate(peripheral.identifier) }
            diagnostic("scan round=\(policy.scanRound) started; service filter active")
            centralManager.scanForPeripherals(withServices: [Self.serviceUUID])
        }
        if peripheral == nil {
            policy.waitForComputer()
            if viewState.connection.failure == nil { viewState.connection = .waitingComputer }
        }
        connectNextCandidate()
        if peripheral == nil && allowRememberedTarget && !rememberedTargetRejected && !enrolling,
           let target = viewState.target {
            if rememberedPeripheral == nil {
                rememberedPeripheral = centralManager.retrievePeripherals(withIdentifiers: [target.peripheralID]).first
            }
            if let rememberedPeripheral { connect(rememberedPeripheral, newAttempt: true) }
        }
        publish()
    }

    private func connectNextCandidate() {
        guard peripheral == nil, shouldConnect, !candidates.isEmpty else { return }
        let candidate = candidates.removeFirst()
        connect(candidate, newAttempt: true)
    }

    private func connect(_ candidate: CBPeripheral, newAttempt: Bool) {
        guard peripheral == nil, shouldConnect, disconnectAction == nil else { return }
        if newAttempt { policy.resetConnectionRetries() }
        peripheral = candidate
        candidate.delegate = self
        let remembered = !enrolling &&
            (candidate === rememberedPeripheral || candidate.identifier == viewState.target?.peripheralID)
        policy.connecting(now: now, rememberedTarget: remembered)
        viewState.connection = remembered ? .waitingComputer : .connecting
        viewState.issue = nil
        diagnostic("candidate connecting remembered=\(remembered) scanRound=\(policy.scanRound)")
        startInitializationTimeout()
        if candidate.state == .connected {
            policy.connected(now: now)
            startInitializationTimeout()
            discoverServices(candidate)
        } else if candidate.state == .disconnected { centralManager.connect(candidate) }
        publish()
    }

    func centralManagerDidUpdateState(_ central: CBCentralManager) {
        diagnostic("central state=\(central.state.rawValue)")
        guard central.state == .poweredOn else {
            central.stopScan()
            discardAuthentication(message: "蓝牙不可用，本次请求已失效")
            if enrolling {
                enrolling = false
                enrollmentSent = false
                viewState.enrollment = .failed("蓝牙不可用，登记未完成，原目标保留")
            }
            clearDisconnectedState()
            rememberedPeripheral = nil
            retryCandidate = nil
            candidates.removeAll()
            viewState.connection = .bluetoothUnavailable
            publish()
            return
        }
        beginSearch()
    }

    func centralManager(_ central: CBCentralManager, willRestoreState dict: [String: Any]) {
        diagnostic("restoration received")
        let restored = (dict[CBCentralManagerRestoredStatePeripheralsKey] as? [CBPeripheral] ?? []).sorted {
            ($0.identifier == viewState.target?.peripheralID ? 0 : 1) <
                ($1.identifier == viewState.target?.peripheralID ? 0 : 1)
        }
        for item in restored {
            guard shouldConnect, peripheral == nil, viewState.target != nil else {
                central.cancelPeripheralConnection(item)
                continue
            }
            peripheral = item
            item.delegate = self
            if item.identifier == viewState.target?.peripheralID { rememberedPeripheral = item }
            if item.state == .connected {
                policy.connected(now: now)
                startInitializationTimeout()
                discoverServices(item)
            } else {
                let remembered = item.identifier == viewState.target?.peripheralID
                policy.connecting(now: now, rememberedTarget: remembered)
                viewState.connection = remembered ? .waitingComputer : .connecting
                startInitializationTimeout()
                if item.state == .disconnected { central.connect(item) }
            }
        }
        if central.state == .poweredOn { beginSearch() }
    }

    func centralManager(_ central: CBCentralManager, didDiscover candidate: CBPeripheral,
                        advertisementData: [String: Any], rssi RSSI: NSNumber) {
        guard shouldConnect, policy.phase != .ready else { return }
        if candidate === peripheral {
            guard candidate.state == .connected, policy.isPassiveWait, disconnectAction == nil,
                  policy.discoverCandidate(candidate.identifier) else { return }
            rediscoverServices(candidate, trigger: "service advertisement")
            return
        }
        guard candidates.count < 16, !candidates.contains(where: { $0.identifier == candidate.identifier }),
              policy.discoverCandidate(candidate.identifier) else { return }
        if candidate.identifier == viewState.target?.peripheralID { candidates.insert(candidate, at: 0) }
        else { candidates.append(candidate) }
        diagnostic("candidate discovered scanRound=\(policy.scanRound) passiveWait=\(policy.isPassiveWait)")
        if peripheral != nil && policy.isPassiveWait && disconnectAction == nil {
            diagnostic("new candidate replacing passive wait; serialized disconnect")
            disconnect(action: .search)
            return
        }
        connectNextCandidate()
    }

    func centralManager(_ central: CBCentralManager, didConnect candidate: CBPeripheral) {
        guard peripheral === candidate, shouldConnect, disconnectAction == nil else {
            central.cancelPeripheralConnection(candidate)
            return
        }
        diagnostic("connected; discovery starting")
        viewState.issue = nil
        policy.connected(now: now)
        clearCharacteristics()
        startInitializationTimeout()
        discoverServices(candidate)
    }

    func centralManager(_ central: CBCentralManager, didFailToConnect candidate: CBPeripheral, error: Error?) {
        guard peripheral === candidate else { return }
        diagnostic("connection attempt failed code=\((error as NSError?)?.code ?? 0)")
        let action = disconnectAction
        disconnectAction = nil
        clearDisconnectedState()
        if let action { resumeAfterDisconnect(action); return }
        failWithoutConnection("无法建立蓝牙连接", candidate: candidate, retry: true)
    }

    func centralManager(_ central: CBCentralManager, didDisconnectPeripheral candidate: CBPeripheral, error: Error?) {
        guard peripheral === candidate else { return }
        diagnostic("disconnected; approval discarded code=\((error as NSError?)?.code ?? 0)")
        let action = disconnectAction
        let wasWaiting = policy.phase == .ready || policy.phase == .waitingService
        disconnectAction = nil
        discardAuthentication(message: "蓝牙已断开，本次认证已失效")
        clearDisconnectedState()
        if let action { resumeAfterDisconnect(action); return }
        if enrolling && enrollmentSent {
            enrolling = false
            enrollmentSent = false
            viewState.enrollment = .failed("登记连接中断，原目标保留")
        }
        failWithoutConnection("蓝牙连接已断开", candidate: candidate, retry: !wasWaiting)
    }

    private func failWithoutConnection(_ message: String, candidate: CBPeripheral, retry: Bool) {
        diagnostic("connection ended; retry=\(retry) remaining=\(policy.remainingConnectionRetries)")
        if !retry {
            viewState.issue = nil
            viewState.connection = .waitingComputer
            beginSearch()
        } else if shouldConnect && policy.takeConnectionRetry() {
            diagnostic("recovery retry remaining=\(policy.remainingConnectionRetries)")
            connect(candidate, newAttempt: false)
            beginSearch(allowRememberedTarget: false)
        } else {
            viewState.connection = .failed(message + "；仍在等待电脑恢复")
            if enrolling {
                enrolling = false
                viewState.enrollment = .failed(message + "；原目标保留")
            }
            beginSearch(allowRememberedTarget: false)
        }
    }

    private func disconnect(action: DisconnectAction) {
        if action == .halt || action == .resume { centralManager.stopScan() }
        if action != .recover { retryCandidate = nil }
        discardAuthentication(message: "连接已结束，本次认证已失效")
        if action != .halt { viewState.connection = .recovering }
        else { viewState.connection = viewState.target == nil ? .unregistered : .waitingComputer }
        guard let peripheral else { resumeAfterDisconnect(action); return }
        if action == .recover {
            retryCandidate = peripheral
        }
        if peripheral.state == .disconnected {
            clearDisconnectedState()
            resumeAfterDisconnect(action)
            return
        }
        disconnectAction = action
        initializationTimeout?.cancel()
        initializationTimeout = nil
        clearCharacteristics()
        policy.failed()
        centralManager.cancelPeripheralConnection(peripheral)
    }

    private func resumeAfterDisconnect(_ action: DisconnectAction) {
        switch action {
        case .recover:
            let candidate = retryCandidate
            retryCandidate = nil
            if let candidate { connect(candidate, newAttempt: false) }
            beginSearch(allowRememberedTarget: false)
        case .search: beginSearch()
        case .resume:
            candidates.removeAll()
            beginSearch()
        case .halt:
            if shouldConnect { beginSearch(); return }
            viewState.connection = viewState.target == nil ? .unregistered : .waitingComputer
            publish()
        }
    }

    private func failConnection(_ message: String) {
        guard disconnectAction == nil else { return }
        let stage = String(describing: policy.phase)
        let failure = "\(message)（阶段：\(stage)）；仍在等待电脑恢复"
        let elapsed = policy.deadline.map { max(0, now - ($0 - BluetoothAuthenticationState.initializationLifetime)) }
        diagnostic("initialization or transport failed phase=\(stage) elapsed=\(elapsed ?? 0) retryRemaining=\(policy.remainingConnectionRetries)")
        viewState.issue = nil
        discardAuthentication(message: message)
        if enrolling && enrollmentSent {
            enrolling = false
            enrollmentSent = false
            viewState.enrollment = .failed(message + "；登记未确认，原目标保留")
        }
        let retry = shouldConnect && policy.takeConnectionRetry()
        if retry {
            viewState.connection = .recovering
            disconnect(action: .recover)
        } else {
            if enrolling { enrolling = false; viewState.enrollment = .failed(message) }
            initializationTimeout?.cancel()
            initializationTimeout = nil
            clearCharacteristics()
            policy.failed()
            viewState.connection = .failed(failure)
            if peripheral?.state == .connected { beginSearch(allowRememberedTarget: false) }
            else { disconnect(action: .search) }
            viewState.connection = .failed(failure)
        }
        publish()
    }

    private func rejectCandidate(_ message: String) {
        diagnostic("candidate rejected during identity verification")
        if let peripheral, peripheral === rememberedPeripheral || peripheral.identifier == viewState.target?.peripheralID {
            rememberedTargetRejected = true
            rememberedPeripheral = nil
        }
        viewState.issue = message
        if enrolling {
            enrolling = false
            enrollmentSent = false
            viewState.enrollment = .failed(message + "；原目标保留")
            viewState.connection = .failed(message)
            disconnect(action: .halt)
        } else { disconnect(action: .search) }
        publish()
    }

    private func waitForService() {
        diagnostic("service absent; connected passive wait")
        discardAuthentication(message: "解锁服务暂时不可用，本次认证已失效")
        if enrolling {
            enrolling = false
            enrollmentSent = false
            viewState.enrollment = .failed("本次未发现登记服务；原目标保留，请在 Windows 开启配对")
        }
        initializationTimeout?.cancel()
        initializationTimeout = nil
        clearCharacteristics()
        serviceInDiscovery = nil
        identityReadInDiscovery = nil
        policy.waitForService()
        viewState.issue = nil
        viewState.connection = .waitingService
        if shouldConnect { beginSearch(allowRememberedTarget: false) }
        else { disconnect(action: .halt) }
        publish()
    }

    private func rediscoverServices(_ peripheral: CBPeripheral, trigger: String) {
        diagnostic("service recovery trigger=\(trigger) pending=\(discoveryOperation != nil)")
        discardAuthentication(message: "服务发生变化，本次认证已取消，请在 Windows 发起新请求")
        clearCharacteristics()
        viewState.issue = nil
        let discover = policy.invalidateServices(now: now, discoveryPending: discoveryOperation != nil)
        viewState.connection = .recovering
        startInitializationTimeout()
        if discover { discoverServices(peripheral) }
        publish()
    }

    private func startInitializationTimeout() {
        initializationTimeout?.cancel()
        guard let deadline = policy.deadline, let current = peripheral else { return }
        initializationTimeout = Task { [weak self] in
            do { try await Task.sleep(for: .seconds(max(0, deadline - ProcessInfo.processInfo.systemUptime))) }
            catch { return }
            guard let self, self.peripheral === current, self.policy.deadline == deadline else { return }
            self.failConnection("连接／服务初始化超过 10 秒")
        }
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
            failConnection("服务恢复超过 10 秒")
            return false
        }
    }

    func peripheral(_ peripheral: CBPeripheral, didDiscoverServices error: Error?) {
        guard self.peripheral === peripheral, discoveryOperation == .services else { return }
        discoveryOperation = nil
        guard advanceDiscovery(peripheral) else { return }
        if let error { failConnection("发现服务失败：\(error.localizedDescription)"); return }
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
        if let error { failConnection("发现特征失败：\(error.localizedDescription)"); return }
        guard let chars = service.characteristics,
              let request = chars.first(where: { $0.uuid == Self.requestCharacteristicUUID }),
              let challenge = chars.first(where: { $0.uuid == Self.challengeCharacteristicUUID }),
              let assertion = chars.first(where: { $0.uuid == Self.assertionCharacteristicUUID }),
              let result = chars.first(where: { $0.uuid == Self.resultCharacteristicUUID }) else {
            failConnection("Windows 解锁服务缺少必要特征")
            return
        }
        guard let identity = chars.first(where: { $0.uuid == Self.computerIDCharacteristicUUID }),
              identity.properties.contains(.read) else {
            rejectCandidate("Windows 版本不支持稳定 ComputerId，请更新 Windows 组件")
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
        if let error { failConnection("通知订阅失败：\(error.localizedDescription)"); return }
        guard characteristic.isNotifying else { failConnection("Windows 通知订阅已失效"); return }
        finishSubscriptions(peripheral)
    }

    private func finishSubscriptions(_ peripheral: CBPeripheral) {
        let challenge = challengeCharacteristic?.isNotifying == true
        let result = resultCharacteristic?.isNotifying == true
        diagnostic("subscriptions challenge=\(challenge) result=\(result)")
        guard policy.subscriptions(challenge: challenge, result: result, now: now) else { return }
        initializationTimeout?.cancel()
        initializationTimeout = nil
        centralManager.stopScan()
        candidates.removeAll()
        viewState.connection = .ready
        viewState.issue = nil
        diagnostic("ready; computer identity verified")
        if enrolling { sendEnrollment(peripheral) }
        else if var target = viewState.target {
            target.peripheralID = peripheral.identifier
            saveTarget(target)
        }
        publish()
    }

    private func sendEnrollment(_ peripheral: CBPeripheral) {
        guard !enrollmentSent, let requestCharacteristic, policy.verifiedComputerID != nil else { return }
        do {
            let key = try keyStore.publicKeyRawRepresentation()
            guard key.count == 65 else { throw UnlockError.protocolEncodingFailed("公钥长度无效") }
            var request = Data([0x02])
            request.append(key)
            enrollmentSent = true
            viewState.enrollment = .waitingConfirmation
            guard write(request, to: requestCharacteristic, purpose: .enrollment(enrollmentSequence)) else { return }
            diagnostic("enrollment sent; waiting Windows confirmation")
        } catch {
            enrolling = false
            viewState.enrollment = .failed("无法提交登记：\(error.localizedDescription)")
        }
    }

    private func saveTarget(_ target: RegisteredComputer) {
        do {
            let data = try JSONEncoder().encode(target)
            defaults.set(data, forKey: "registeredWindowsComputer")
            defaults.removeObject(forKey: "unlockTargetPeripheral")
            viewState.target = target
        } catch {
            viewState.issue = "无法保存目标电脑信息：\(error.localizedDescription)"
            if enrolling { viewState.enrollment = .failed("目标电脑信息未保存，原目标保留") }
        }
    }

    func peripheral(_ peripheral: CBPeripheral, didUpdateValueFor characteristic: CBCharacteristic, error: Error?) {
        guard self.peripheral === peripheral else { return }
        if characteristic === identityReadInDiscovery && discoveryOperation == .identity {
            discoveryOperation = nil
            guard advanceDiscovery(peripheral) else { return }
            guard error == nil, let data = characteristic.value,
                  let id = BluetoothAuthenticationState.computerID(from: data) else {
                rejectCandidate("Windows ComputerId 缺失或格式无效")
                return
            }
            guard policy.verifyComputer(id, expected: viewState.target?.computerID, enrolling: enrolling) else {
                diagnostic("candidate identity mismatch")
                rejectCandidate("发现的电脑不是已登记目标，未发送签名")
                return
            }
            if !enrolling {
                rememberedPeripheral = peripheral
                rememberedTargetRejected = false
            }
            let name = peripheral.name?.trimmingCharacters(in: .whitespacesAndNewlines) ?? ""
            viewState.connectedComputer = RegisteredComputer(computerID: id,
                name: name.isEmpty ? "Windows 电脑" : name, peripheralID: peripheral.identifier)
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
        guard policy.phase == .ready,
              characteristic === resultCharacteristic || characteristic === challengeCharacteristic else { return }
        if let error { failConnection("蓝牙通知失败：\(error.localizedDescription)"); return }
        guard let data = characteristic.value else { failConnection("Windows 通知没有数据"); return }
        if characteristic === resultCharacteristic { handleWindowsResult(data, peripheral: peripheral) }
        else { handleChallenge(data, peripheral: peripheral) }
    }

    private struct WindowsResult: Decodable {
        let authenticated: Bool
        let status: String
        let detail: String?
        let requestID: UUID?
    }

    private func handleWindowsResult(_ data: Data, peripheral: CBPeripheral) {
        do {
            let result = try JSONDecoder().decode(WindowsResult.self, from: data)
            if let outcome = BluetoothAuthenticationState.enrollmentOutcome(code: result.status, detail: result.detail) {
                guard enrolling, enrollmentSent, let id = policy.verifiedComputerID else { return }
                diagnostic("Windows enrollment result=\(allowedResult(result.status)) reloadFailed=\(result.detail == "saved_reload_failed")")
                let name = peripheral.name?.trimmingCharacters(in: .whitespacesAndNewlines) ?? ""
                let candidate = RegisteredComputer(computerID: id,
                    name: name.isEmpty ? "已登记 Windows 电脑" : name, peripheralID: peripheral.identifier)
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
                else if !viewState.automaticEnabled { disconnect(action: .halt) }
                publish()
                return
            }
            if result.status.hasPrefix("enrollment_") {
                if enrolling && enrollmentSent {
                    enrolling = false
                    enrollmentSent = false
                    viewState.enrollment = .failed("Windows 返回未知登记结果，未修改原目标")
                    disconnect(action: .resume)
                    publish()
                }
                diagnostic("unknown or stale enrollment result ignored")
                return
            }
            if result.requestID == nil && (pendingChallenge != nil || awaitingResultID != nil) {
                finishPending()
                viewState.authentication = .rejected("Windows 认证结果缺少 requestID，请重新发起")
                diagnostic("authentication result missing request association")
                publish()
                return
            }
            guard BluetoothAuthenticationState.acceptsResult(requestID: result.requestID,
                pending: pendingChallenge?.requestID, awaiting: awaitingResultID) else { return }
            diagnostic("Windows authentication result=\(allowedResult(result.status)) authenticated=\(result.authenticated)")
            finishPending()
            if result.authenticated && result.status == "unlock_approved" {
                viewState.authentication = .approved
            } else {
                viewState.authentication = .rejected(authenticationFailureText(result.status))
            }
            publish()
        } catch {
            viewState.issue = "Windows 返回结果格式无效"
            diagnostic("Windows result decoding failed")
            publish()
        }
    }

    private func handleChallenge(_ data: Data, peripheral: CBPeripheral) {
        do {
            let challenge = try UnlockProtocol.decodeChallenge(from: data)
            guard challenge.requestID != lastHandledRequest else { return }
            if pendingChallenge != nil { rejectPending(reason: 6, message: "新请求替代了旧请求") }
            finishPending()
            pendingChallenge = challenge
            pendingDeadline = now + BluetoothAuthenticationState.responseLifetime
            lastHandledRequest = challenge.requestID
            guard challenge.version == 1, challenge.audience == "windows-unlock", challenge.nonce.count == 32 else {
                rejectPending(reason: 6, message: "Windows 请求格式无效")
                return
            }
            guard policy.acceptsAuthentication(target: viewState.target?.computerID,
                enabled: viewState.automaticEnabled, enrolling: enrolling) else {
                rejectPending(reason: 2, message: "目标未登记、正在登记或自动响应已暂停")
                return
            }
            viewState.authentication = .readingRSSI
            diagnostic("challenge received foreground=\(foreground); fresh RSSI required")
            let id = challenge.requestID
            authenticationTimeout = Task { [weak self] in
                do { try await Task.sleep(for: .seconds(BluetoothAuthenticationState.responseLifetime)) }
                catch { return }
                guard let self, self.pendingChallenge?.requestID == id else { return }
                self.rejectPending(reason: 3, message: "本次新 RSSI／签名处理超过 3 秒")
            }
            readChallengeRSSI(peripheral)
            publish()
        } catch {
            viewState.authentication = .rejected("Windows challenge 格式无效")
            diagnostic("challenge decoding failed")
            publish()
        }
    }

    private func readChallengeRSSI(_ peripheral: CBPeripheral) {
        guard let challenge = pendingChallenge else { return }
        guard now < pendingDeadline else {
            rejectPending(reason: 3, message: "本次 RSSI 响应已过期")
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
                self.rejectPending(reason: 3, message: "未收到本次 RSSI 回调")
            }
            self.failConnection("RSSI 回调超时，连接需要恢复")
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
            rejectPending(reason: 3, message: "本次 RSSI 读取失败")
            return
        }
        let decision = BluetoothAuthenticationState.signalDecision(rssi: value, threshold: viewState.threshold,
            now: now, deadline: pendingDeadline)
        guard decision != .invalid else { rejectPending(reason: 3, message: "本次 RSSI 读数无效"); return }
        guard decision != .expired else { rejectPending(reason: 3, message: "本次 RSSI 响应已过期"); return }
        viewState.rssi = value
        viewState.rssiMeasuredAt = Date()
        diagnostic("fresh RSSI=\(value) threshold=\(viewState.threshold)")
        guard decision == .approve else {
            rejectPending(reason: 1, message: "RSSI 不足：\(value) dBm，阈值 \(viewState.threshold) dBm")
            return
        }
        guard policy.acceptsAuthentication(target: viewState.target?.computerID,
            enabled: viewState.automaticEnabled, enrolling: enrolling), let assertionCharacteristic else {
            rejectPending(reason: 2, message: "当前连接不具备批准资格")
            return
        }
        do {
            viewState.authentication = .signing
            publish()
            let assertion = try UnlockProtocol.sign(challenge: challenge, using: keyStore)
            let data = try UnlockProtocol.encode(assertion: assertion)
            guard now < pendingDeadline else {
                rejectPending(reason: 6, message: "签名完成时本次请求已过期")
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
        } catch { rejectPending(reason: 6, message: "本次签名失败：\(error.localizedDescription)") }
    }

    private func write(_ data: Data, to characteristic: CBCharacteristic, purpose: WritePurpose) -> Bool {
        guard let peripheral, peripheral.state == .connected, policy.phase == .ready else { return false }
        guard writes.values.reduce(0, { $0 + $1.count }) < 16 else {
            failConnection("之前的蓝牙写入尚未确认，连接需要恢复")
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
        guard error != nil, policy.phase == .ready, policy.isCurrentGeneration(context.generation) else { return }
        switch context.purpose {
        case let .assertion(id):
            guard id == awaitingResultID, characteristic === assertionCharacteristic else { return }
            if let requestCharacteristic {
                var reject = Data([0x03])
                reject.append(Data(id.uuidString.lowercased().utf8))
                reject.append(6)
                _ = write(reject, to: requestCharacteristic, purpose: .rejection(id))
            }
            finishPending()
            viewState.authentication = .rejected("签名发送失败，请在 Windows 发起新请求")
        case let .enrollment(sequence):
            guard enrolling, enrollmentSent, sequence == enrollmentSequence else { return }
            enrolling = false
            enrollmentSent = false
            viewState.enrollment = .failed("登记发送失败，原目标保留")
            disconnect(action: .resume)
        case let .rejection(id):
            guard id == awaitingResultID else { return }
            viewState.issue = "手机拒绝结果未能送达 Windows"
        }
        diagnostic("BLE write failed for current operation")
        publish()
    }

    func peripheral(_ peripheral: CBPeripheral, didModifyServices invalidatedServices: [CBService]) {
        guard self.peripheral === peripheral, peripheral.state == .connected,
              disconnectAction == nil,
              policy.isPassiveWait || invalidatedServices.contains(where: { $0.uuid == Self.serviceUUID }) else { return }
        diagnostic("GATT service invalidated; rediscovering without forced disconnect")
        discardAuthentication(message: "服务发生变化，本次认证已取消，请在 Windows 发起新请求")
        if enrolling && enrollmentSent {
            enrolling = false
            enrollmentSent = false
            viewState.enrollment = .failed("登记期间服务发生变化，结果未确认，原目标保留")
        }
        rediscoverServices(peripheral, trigger: "GATT service change")
    }

    private func rejectPending(reason: UInt8, message: String) {
        guard let challenge = pendingChallenge else { return }
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
        pendingChallenge = nil
        awaitingResultID = nil
        authenticationTimeout?.cancel()
        authenticationTimeout = nil
    }

    private func discardAuthentication(message: String) {
        if !viewState.automaticEnabled { viewState.authentication = .paused }
        else if pendingChallenge != nil || awaitingResultID != nil { viewState.authentication = .rejected(message) }
        else { viewState.authentication = .waiting }
        finishPending()
    }

    private func clearCharacteristics() {
        viewState.connectedComputer = nil
        requestCharacteristic = nil
        challengeCharacteristic = nil
        assertionCharacteristic = nil
        resultCharacteristic = nil
    }

    private func clearDisconnectedState() {
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

    private func publish() { onUpdate?(viewState) }

    private func diagnostic(_ event: String) {
        let text = "\(Int(now))s \(event)"
        logger.info("\(text, privacy: .public)")
        onDiagnostic?(text)
    }

    private func allowedResult(_ code: String) -> String {
        let allowed = ["enrollment_saved", "enrollment_already_registered", "enrollment_cancelled",
            "enrollment_rejected", "enrollment_busy", "enrollment_expired", "enrollment_error", "enrollment_removed",
            "unlock_approved", "challenge_expired", "session_changed", "phone_rejected", "not_ready",
            "malformed_json", "unsupported_version", "invalid_request_id", "request_mismatch", "challenge_replayed",
            "key_not_enrolled", "invalid_key_id", "invalid_public_key", "key_id_mismatch", "invalid_signature_encoding",
            "invalid_signature", "unlock_cooldown", "cryptographic_api_failure", "service_error", "service_unavailable"]
        return allowed.contains(code) ? code : "unknown_result"
    }

    private func authenticationFailureText(_ code: String) -> String {
        switch code {
        case "challenge_expired": "Windows 本次认证已超时，请重新按 Enter"
        case "session_changed": "Windows 控制台或锁屏会话已改变，请重新发起"
        case "phone_rejected": viewState.authentication.title
        case "service_error", "service_unavailable": "Windows 认证服务不可用"
        case "not_ready": "Windows 当前不具备解锁条件"
        default: "Windows 拒绝本次认证：\(allowedResult(code))"
        }
    }
}
