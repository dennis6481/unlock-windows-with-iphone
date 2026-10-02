// Created by Rui MA on 26 Sep 2026

@preconcurrency import CoreBluetooth
import Foundation
import UIKit

enum BluetoothUnlockError: LocalizedError {
    case bluetoothUnavailable(CBManagerState)
    case serviceNotFound
    case characteristicMissing(String)
    case connectionFailed(String)
    case receivedInvalidChallenge(String)
    case transportEncodingFailed(String)
    case writeFailed(String)

    var errorDescription: String? {
        switch self {
        case let .bluetoothUnavailable(state):
            return "CoreBluetooth 当前不可用，状态码：\(state.rawValue)。"
        case .serviceNotFound:
            return "已连接设备没有提供项目定义的认证 service。"
        case let .characteristicMissing(name):
            return "认证 service 缺少 characteristic：\(name)。"
        case let .connectionFailed(message):
            return "连接 Windows GATT host 失败：\(message)"
        case let .receivedInvalidChallenge(message):
            return "收到的 challenge 被拒绝：\(message)"
        case let .transportEncodingFailed(message):
            return "BLE 消息编码失败：\(message)"
        case let .writeFailed(message):
            return "BLE 写入失败：\(message)"
        }
    }
}

@MainActor
final class BluetoothAuthenticator: NSObject, @preconcurrency CBCentralManagerDelegate, @preconcurrency CBPeripheralDelegate {
    static let serviceUUID = CBUUID(string: "F1E2D3C4-B5A6-4789-8012-3456789ABCDE")
    static let requestCharacteristicUUID = CBUUID(string: "F1E2D3C4-B5A6-4789-8012-3456789ABCD1")
    static let challengeCharacteristicUUID = CBUUID(string: "F1E2D3C4-B5A6-4789-8012-3456789ABCD2")
    static let assertionCharacteristicUUID = CBUUID(string: "F1E2D3C4-B5A6-4789-8012-3456789ABCD3")
    static let resultCharacteristicUUID = CBUUID(string: "F1E2D3C4-B5A6-4789-8012-3456789ABCD4")

    private let keyStore: SecureEnclaveKeyStore
    private let defaults: UserDefaults
    private(set) var automaticEnabled: Bool
    private(set) var threshold: Int
    private(set) var targetIdentifier: UUID?
    var onError: ((String) -> Void)?
    var onResult: ((String) -> Void)?
    var onStatus: ((String) -> Void)?
    var onRSSI: ((Int?) -> Void)?
    var onTarget: ((UUID) -> Void)?
    private lazy var centralManager = CBCentralManager(
        delegate: self, queue: nil,
        options: [CBCentralManagerOptionRestoreIdentifierKey: "com.example.unlock-windows-with-iphone.central"]
    )
    private var wantsConnection = false
    private var enrolling = false
    private var enrollmentSent = false
    private var peripheral: CBPeripheral?
    private var requestCharacteristic: CBCharacteristic?
    private var assertionCharacteristic: CBCharacteristic?
    private var challengeCharacteristic: CBCharacteristic?
    private var resultCharacteristic: CBCharacteristic?
    private var pendingChallenge: UnlockChallenge?
    private var pendingDeadline = 0.0
    private var awaitingResultID: UUID?
    private var lastHandledRequest: UUID?
    private var rssiReadInFlight = false
    private var rssiRequestID: UUID?
    private var requestTimeout: Task<Void, Never>?
    private var displayTask: Task<Void, Never>?
    private var foreground = false

    init(keyStore: SecureEnclaveKeyStore = SecureEnclaveKeyStore(), defaults: UserDefaults = .standard) {
        self.keyStore = keyStore
        self.defaults = defaults
        automaticEnabled = defaults.bool(forKey: "automaticUnlockEnabled")
        threshold = defaults.object(forKey: "unlockRSSIThreshold") as? Int ?? -60
        targetIdentifier = defaults.string(forKey: "unlockTargetPeripheral").flatMap(UUID.init(uuidString:))
        super.init()
    }

    func activate() {
        wantsConnection = automaticEnabled && targetIdentifier != nil
        _ = centralManager
        if automaticEnabled && targetIdentifier == nil { onStatus?("请先登记目标 Windows 电脑") }
    }

    func setAutomaticEnabled(_ enabled: Bool) {
        automaticEnabled = enabled
        defaults.set(enabled, forKey: "automaticUnlockEnabled")
        if enabled {
            do { try start() } catch { record(error) }
        } else {
            rejectPending(reason: 2)
            if !enrolling { stop() }
        }
    }

    func setThreshold(_ value: Int) {
        threshold = value
        defaults.set(value, forKey: "unlockRSSIThreshold")
    }

    func start() throws {
        guard targetIdentifier != nil else {
            throw BluetoothUnlockError.connectionFailed("请先通过 Windows 托盘配对并在手机登记目标电脑。")
        }
        enrolling = false
        enrollmentSent = false
        wantsConnection = true
        connectTargetIfReady()
    }

    func startEnrollment() throws {
        rejectPending(reason: 6)
        enrolling = true
        enrollmentSent = false
        wantsConnection = true
        if let peripheral, peripheral.state == .connected {
            prepareConnection(peripheral)
        } else if centralManager.state == .poweredOn {
            onStatus?("正在扫描配对窗口，请在 Windows 托盘开启配对")
            centralManager.scanForPeripherals(withServices: [Self.serviceUUID])
        }
    }

    func stop() {
        wantsConnection = false
        enrolling = false
        centralManager.stopScan()
        rejectPending(reason: 2)
        if let peripheral { centralManager.cancelPeripheralConnection(peripheral) }
        clearConnectionState()
        onStatus?("已停止连接")
    }

    func setForeground(_ active: Bool) {
        foreground = active
        displayTask?.cancel()
        displayTask = nil
        guard active else { return }
        displayTask = Task { [weak self] in
            while !Task.isCancelled {
                self?.readDisplayRSSI()
                do { try await Task.sleep(for: .seconds(1)) } catch { return }
            }
        }
    }

    private func connectTargetIfReady() {
        guard wantsConnection, centralManager.state == .poweredOn else { return }
        if let peripheral, peripheral.state == .connected || peripheral.state == .connecting {
            if peripheral.state == .connected { prepareConnection(peripheral) }
            return
        }
        guard let targetIdentifier else { return }
        if let target = centralManager.retrievePeripherals(withIdentifiers: [targetIdentifier]).first {
            peripheral = target
            target.delegate = self
            onStatus?("正在连接目标 Windows 电脑")
            centralManager.connect(target)
        } else {
            onStatus?("正在扫描目标 Windows 电脑")
            centralManager.scanForPeripherals(withServices: [Self.serviceUUID])
        }
    }

    func centralManagerDidUpdateState(_ central: CBCentralManager) {
        guard central.state == .poweredOn else {
            if central.state != .unknown && central.state != .resetting {
                record(BluetoothUnlockError.bluetoothUnavailable(central.state))
            }
            clearConnectionState()
            return
        }
        if enrolling && wantsConnection { central.scanForPeripherals(withServices: [Self.serviceUUID]) }
        else { connectTargetIfReady() }
    }

    func centralManager(_ central: CBCentralManager, willRestoreState dict: [String: Any]) {
        guard let restored = dict[CBCentralManagerRestoredStatePeripheralsKey] as? [CBPeripheral] else { return }
        for item in restored {
            guard automaticEnabled, item.identifier == targetIdentifier else {
                central.cancelPeripheralConnection(item)
                continue
            }
            wantsConnection = true
            peripheral = item
            item.delegate = self
            if item.state == .connected { prepareConnection(item) }
            else if item.state == .disconnected { central.connect(item) }
        }
    }

    func centralManager(_ central: CBCentralManager, didDiscover peripheral: CBPeripheral,
                        advertisementData: [String: Any], rssi RSSI: NSNumber) {
        guard wantsConnection, enrolling || peripheral.identifier == targetIdentifier else { return }
        guard self.peripheral == nil || self.peripheral?.state == .disconnected else { return }
        self.peripheral = peripheral
        peripheral.delegate = self
        central.stopScan()
        central.connect(peripheral)
    }

    func centralManager(_ central: CBCentralManager, didConnect peripheral: CBPeripheral) {
        guard self.peripheral === peripheral, wantsConnection else {
            central.cancelPeripheralConnection(peripheral)
            return
        }
        prepareConnection(peripheral)
    }

    func centralManager(_ central: CBCentralManager, didFailToConnect peripheral: CBPeripheral, error: Error?) {
        guard self.peripheral === peripheral else { return }
        clearConnectionState()
        record(BluetoothUnlockError.connectionFailed(error?.localizedDescription ?? "系统没有提供详细错误。"))
    }

    func centralManager(_ central: CBCentralManager, didDisconnectPeripheral peripheral: CBPeripheral, error: Error?) {
        guard self.peripheral === peripheral else { return }
        clearConnectionState()
        if let error { record(BluetoothUnlockError.connectionFailed(error.localizedDescription)) }
        else { onStatus?("连接已断开") }
        if enrolling { enrolling = false; enrollmentSent = false }
        if wantsConnection && automaticEnabled { connectTargetIfReady() }
    }

    private func prepareConnection(_ peripheral: CBPeripheral) {
        peripheral.delegate = self
        onStatus?("已连接，正在准备订阅")
        if let service = peripheral.services?.first(where: { $0.uuid == Self.serviceUUID }) {
            let uuids = [Self.requestCharacteristicUUID, Self.challengeCharacteristicUUID,
                         Self.assertionCharacteristicUUID, Self.resultCharacteristicUUID]
            if let characteristics = service.characteristics,
               uuids.allSatisfy({ uuid in characteristics.contains(where: { $0.uuid == uuid }) }) {
                prepareCharacteristics(characteristics, peripheral: peripheral)
            } else { peripheral.discoverCharacteristics(uuids, for: service) }
        } else { peripheral.discoverServices([Self.serviceUUID]) }
    }

    func peripheral(_ peripheral: CBPeripheral, didDiscoverServices error: Error?) {
        guard self.peripheral === peripheral else { return }
        if let error { record(error); return }
        guard let service = peripheral.services?.first(where: { $0.uuid == Self.serviceUUID }) else {
            record(BluetoothUnlockError.serviceNotFound)
            return
        }
        peripheral.discoverCharacteristics([Self.requestCharacteristicUUID, Self.challengeCharacteristicUUID,
            Self.assertionCharacteristicUUID, Self.resultCharacteristicUUID], for: service)
    }

    func peripheral(_ peripheral: CBPeripheral, didDiscoverCharacteristicsFor service: CBService, error: Error?) {
        guard self.peripheral === peripheral else { return }
        if let error { record(error); return }
        guard let characteristics = service.characteristics else {
            record(BluetoothUnlockError.characteristicMissing("全部 characteristic"))
            return
        }
        prepareCharacteristics(characteristics, peripheral: peripheral)
    }

    private func prepareCharacteristics(_ characteristics: [CBCharacteristic], peripheral: CBPeripheral) {
        requestCharacteristic = characteristics.first { $0.uuid == Self.requestCharacteristicUUID }
        challengeCharacteristic = characteristics.first { $0.uuid == Self.challengeCharacteristicUUID }
        assertionCharacteristic = characteristics.first { $0.uuid == Self.assertionCharacteristicUUID }
        resultCharacteristic = characteristics.first { $0.uuid == Self.resultCharacteristicUUID }
        guard requestCharacteristic != nil, assertionCharacteristic != nil,
              let challengeCharacteristic, let resultCharacteristic else {
            record(BluetoothUnlockError.characteristicMissing("request/challenge/assertion/result"))
            return
        }
        if !challengeCharacteristic.isNotifying { peripheral.setNotifyValue(true, for: challengeCharacteristic) }
        if !resultCharacteristic.isNotifying { peripheral.setNotifyValue(true, for: resultCharacteristic) }
        connectionReady()
    }

    func peripheral(_ peripheral: CBPeripheral, didUpdateNotificationStateFor characteristic: CBCharacteristic, error: Error?) {
        guard self.peripheral === peripheral else { return }
        if let error { record(error); return }
        guard characteristic.isNotifying else {
            record(BluetoothUnlockError.connectionFailed("Windows 通知订阅失效。"))
            return
        }
        connectionReady()
    }

    private func connectionReady() {
        guard let peripheral, resultCharacteristic?.isNotifying == true,
              challengeCharacteristic?.isNotifying == true else { return }
        if enrolling && !enrollmentSent {
            do {
                guard let requestCharacteristic else { throw BluetoothUnlockError.characteristicMissing("request") }
                let key = try keyStore.publicKeyRawRepresentation()
                guard key.count == 65 else { throw BluetoothUnlockError.transportEncodingFailed("公钥不是 65 字节。") }
                var request = Data([0x02])
                request.append(key)
                peripheral.writeValue(request, for: requestCharacteristic, type: .withResponse)
                enrollmentSent = true
                onStatus?("公钥已发送，等待 Windows 指纹确认")
            } catch { record(error) }
        } else if !enrolling { onStatus?("已连接，等待 Windows 箭头发起认证") }
    }

    func peripheral(_ peripheral: CBPeripheral, didUpdateValueFor characteristic: CBCharacteristic, error: Error?) {
        guard self.peripheral === peripheral else { return }
        if let error { record(error); return }
        guard let value = characteristic.value else {
            record(BluetoothUnlockError.transportEncodingFailed("通知没有数据。"))
            return
        }
        if characteristic.uuid == Self.resultCharacteristicUUID {
            do {
                let result = try JSONDecoder().decode(WindowsResult.self, from: value)
                if enrolling && (result.status == "enrollment_saved" || result.status == "enrollment_already_registered") {
                    targetIdentifier = peripheral.identifier
                    defaults.set(peripheral.identifier.uuidString, forKey: "unlockTargetPeripheral")
                    onTarget?(peripheral.identifier)
                }
                if result.status.hasPrefix("enrollment_") { enrolling = false; enrollmentSent = false }
                if !result.status.hasPrefix("enrollment_") {
                    guard let requestID = result.requestID else {
                        throw BluetoothUnlockError.transportEncodingFailed("认证结果缺少 requestID。")
                    }
                    guard requestID == pendingChallenge?.requestID || requestID == awaitingResultID else { return }
                    finishPending()
                }
                onResult?(result.status + (result.detail.map { "：" + $0 } ?? ""))
                if result.authenticated == false && !result.status.hasPrefix("enrollment_") {
                    onStatus?("本次认证失败：" + result.status)
                }
            } catch { record(BluetoothUnlockError.transportEncodingFailed(error.localizedDescription)) }
            return
        }
        guard characteristic.uuid == Self.challengeCharacteristicUUID else { return }
        do {
            let challenge = try UnlockProtocol.decodeChallenge(from: value)
            guard challenge.requestID != lastHandledRequest else { return }
            if pendingChallenge != nil { rejectPending(reason: 6) }
            finishPending()
            pendingChallenge = challenge
            pendingDeadline = ProcessInfo.processInfo.systemUptime + 3
            lastHandledRequest = challenge.requestID
            guard challenge.version == 1, challenge.audience == "windows-unlock", challenge.nonce.count == 32 else {
                rejectPending(reason: 6)
                throw BluetoothUnlockError.receivedInvalidChallenge("版本、audience 或 nonce 无效。")
            }
            guard automaticEnabled, !enrolling, peripheral.identifier == targetIdentifier else {
                rejectPending(reason: 2)
                return
            }
            onStatus?("收到 Windows 请求，正在读取新 RSSI")
            requestTimeout = Task { [weak self] in
                do { try await Task.sleep(for: .seconds(3)) } catch { return }
                guard self?.pendingChallenge?.requestID == challenge.requestID ||
                    self?.awaitingResultID == challenge.requestID else { return }
                if self?.pendingChallenge != nil { self?.rejectPending(reason: 3) }
                else { self?.finishPending() }
                self?.record(BluetoothUnlockError.connectionFailed("读取 RSSI 或批准请求超时。"))
            }
            readChallengeRSSI()
        } catch { record(error) }
    }

    private struct WindowsResult: Decodable {
        let authenticated: Bool
        let status: String
        let detail: String?
        let requestID: UUID?
    }

    private func readDisplayRSSI() {
        guard foreground, pendingChallenge == nil, !rssiReadInFlight,
              let peripheral, peripheral.state == .connected else { return }
        rssiReadInFlight = true
        rssiRequestID = nil
        peripheral.readRSSI()
    }

    private func readChallengeRSSI() {
        guard !rssiReadInFlight, let pendingChallenge, let peripheral, peripheral.state == .connected else { return }
        rssiReadInFlight = true
        rssiRequestID = pendingChallenge.requestID
        peripheral.readRSSI()
    }

    func peripheral(_ peripheral: CBPeripheral, didReadRSSI RSSI: NSNumber, error: Error?) {
        guard self.peripheral === peripheral, rssiReadInFlight else { return }
        let measuredRequest = rssiRequestID
        rssiReadInFlight = false
        rssiRequestID = nil
        let value = RSSI.intValue
        if let error {
            onRSSI?(nil)
            if measuredRequest == pendingChallenge?.requestID && measuredRequest != nil { rejectPending(reason: 3) }
            record(error)
        } else if value == 127 || value >= 0 || value < -127 {
            onRSSI?(nil)
            if measuredRequest == pendingChallenge?.requestID && measuredRequest != nil { rejectPending(reason: 3) }
            record(BluetoothUnlockError.connectionFailed("RSSI 读数无效。"))
        } else {
            onRSSI?(value)
            if let challenge = pendingChallenge, measuredRequest == challenge.requestID {
                guard ProcessInfo.processInfo.systemUptime < pendingDeadline else {
                    rejectPending(reason: 3)
                    record(BluetoothUnlockError.connectionFailed("RSSI 响应已超时。"))
                    return
                }
                guard automaticEnabled else { rejectPending(reason: 2); return }
                guard value >= threshold else {
                    rejectPending(reason: 1)
                    onStatus?("信号不足：\(value) dBm，阈值 \(threshold) dBm")
                    return
                }
                do {
                    guard let assertionCharacteristic else { throw BluetoothUnlockError.characteristicMissing("assertion") }
                    let assertion = try UnlockProtocol.sign(challenge: challenge, using: keyStore)
                    let data = try UnlockProtocol.encode(assertion: assertion)
                    guard ProcessInfo.processInfo.systemUptime < pendingDeadline else {
                        rejectPending(reason: 6)
                        throw BluetoothUnlockError.connectionFailed("签名完成时请求已超时。")
                    }
                    peripheral.writeValue(data, for: assertionCharacteristic, type: .withResponse)
                    awaitingResultID = challenge.requestID
                    pendingChallenge = nil
                    onStatus?("RSSI 达标，签名已发送，等待 Windows 结果")
                } catch { rejectPending(reason: 6); record(error) }
            }
        }
        if pendingChallenge != nil { readChallengeRSSI() }
    }

    func peripheral(_ peripheral: CBPeripheral, didWriteValueFor characteristic: CBCharacteristic, error: Error?) {
        guard self.peripheral === peripheral else { return }
        if let error {
            if characteristic.uuid == Self.assertionCharacteristicUUID, let awaitingResultID,
               let requestCharacteristic, peripheral.state == .connected {
                var rejection = Data([0x03])
                rejection.append(Data(awaitingResultID.uuidString.lowercased().utf8))
                rejection.append(6)
                peripheral.writeValue(rejection, for: requestCharacteristic, type: .withResponse)
            }
            record(BluetoothUnlockError.writeFailed(error.localizedDescription))
        }
    }

    func peripheral(_ peripheral: CBPeripheral, didModifyServices invalidatedServices: [CBService]) {
        guard self.peripheral === peripheral,
              invalidatedServices.contains(where: { $0.uuid == Self.serviceUUID }) else { return }
        clearCharacteristics()
        peripheral.discoverServices([Self.serviceUUID])
    }

    private func rejectPending(reason: UInt8) {
        guard let challenge = pendingChallenge else { return }
        if let peripheral, peripheral.state == .connected, let requestCharacteristic {
            var data = Data([0x03])
            data.append(Data(challenge.requestID.uuidString.lowercased().utf8))
            data.append(reason)
            peripheral.writeValue(data, for: requestCharacteristic, type: .withResponse)
        } else { record(BluetoothUnlockError.connectionFailed("无法发送手机拒绝结果：连接不可用。")) }
        awaitingResultID = challenge.requestID
        pendingChallenge = nil
    }

    private func finishPending() {
        pendingChallenge = nil
        awaitingResultID = nil
        requestTimeout?.cancel()
        requestTimeout = nil
    }

    private func record(_ error: Error) { onError?(error.localizedDescription) }

    private func clearCharacteristics() {
        finishPending()
        requestCharacteristic = nil
        assertionCharacteristic = nil
        challengeCharacteristic = nil
        resultCharacteristic = nil
        enrollmentSent = false
        onRSSI?(nil)
    }

    private func clearConnectionState() {
        clearCharacteristics()
        rssiReadInFlight = false
        rssiRequestID = nil
        peripheral = nil
    }
}
