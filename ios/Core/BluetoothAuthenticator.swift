@preconcurrency import CoreBluetooth
import Foundation

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
    private(set) var lastError: String?
    var onError: ((String) -> Void)?
    private lazy var centralManager = CBCentralManager(
        delegate: self,
        queue: nil,
        options: [CBCentralManagerOptionRestoreIdentifierKey: "com.example.unlock-windows-with-iphone.central"]
    )

    private var wantsToScan = false
    private var peripheral: CBPeripheral?
    private var requestCharacteristic: CBCharacteristic?
    private var challengeCharacteristic: CBCharacteristic?
    private var assertionCharacteristic: CBCharacteristic?
    private var resultCharacteristic: CBCharacteristic?

    init(keyStore: SecureEnclaveKeyStore = SecureEnclaveKeyStore()) {
        self.keyStore = keyStore
        super.init()
        _ = centralManager
    }

    func start() throws {
        lastError = nil
        wantsToScan = true
        guard centralManager.state == .poweredOn else {
            throw BluetoothUnlockError.bluetoothUnavailable(centralManager.state)
        }
        scanForWindowsHost()
    }

    func stop() {
        wantsToScan = false
        centralManager.stopScan()
        if let peripheral {
            centralManager.cancelPeripheralConnection(peripheral)
        }
        clearConnectionState()
    }

    func centralManagerDidUpdateState(_ central: CBCentralManager) {
        guard wantsToScan else { return }
        guard central.state == .poweredOn else {
            record(error: BluetoothUnlockError.bluetoothUnavailable(central.state))
            return
        }
        scanForWindowsHost()
    }

    func centralManager(
        _ central: CBCentralManager,
        willRestoreState dict: [String: Any]
    ) {
        if let restored = dict[CBCentralManagerRestoredStatePeripheralsKey] as? [CBPeripheral],
           let restoredPeripheral = restored.first {
            peripheral = restoredPeripheral
            restoredPeripheral.delegate = self
            central.connect(restoredPeripheral)
        }
    }

    private func scanForWindowsHost() {
        centralManager.scanForPeripherals(
            withServices: [Self.serviceUUID],
            options: [CBCentralManagerScanOptionAllowDuplicatesKey: false]
        )
    }

    func centralManager(
        _ central: CBCentralManager,
        didDiscover peripheral: CBPeripheral,
        advertisementData: [String: Any],
        rssi RSSI: NSNumber
    ) {
        self.peripheral = peripheral
        peripheral.delegate = self
        central.stopScan()
        central.connect(peripheral)
    }

    func centralManager(_ central: CBCentralManager, didConnect peripheral: CBPeripheral) {
        peripheral.delegate = self
        peripheral.discoverServices([Self.serviceUUID])
    }

    func centralManager(
        _ central: CBCentralManager,
        didFailToConnect peripheral: CBPeripheral,
        error: Error?
    ) {
        clearConnectionState()
        if wantsToScan {
            scanForWindowsHost()
        }
        record(error: BluetoothUnlockError.connectionFailed(error?.localizedDescription ?? "系统没有提供详细错误。"))
    }

    func centralManager(
        _ central: CBCentralManager,
        didDisconnectPeripheral peripheral: CBPeripheral,
        error: Error?
    ) {
        if let error {
            record(error: BluetoothUnlockError.connectionFailed(error.localizedDescription))
        }
        clearConnectionState()
        if wantsToScan && central.state == .poweredOn {
            scanForWindowsHost()
        }
    }

    func peripheral(_ peripheral: CBPeripheral, didDiscoverServices error: Error?) {
        guard let error else {
            guard let service = peripheral.services?.first(where: { $0.uuid == Self.serviceUUID }) else {
                record(error: BluetoothUnlockError.serviceNotFound)
                return
            }
            peripheral.discoverCharacteristics(
                [
                    Self.requestCharacteristicUUID,
                    Self.challengeCharacteristicUUID,
                    Self.assertionCharacteristicUUID,
                    Self.resultCharacteristicUUID
                ],
                for: service
            )
            return
        }
        record(error: BluetoothUnlockError.connectionFailed(error.localizedDescription))
    }

    func peripheral(
        _ peripheral: CBPeripheral,
        didDiscoverCharacteristicsFor service: CBService,
        error: Error?
    ) {
        guard let error else {
            guard let characteristics = service.characteristics else {
                record(error: BluetoothUnlockError.characteristicMissing("全部 characteristic"))
                return
            }

            for characteristic in characteristics {
                switch characteristic.uuid {
                case Self.requestCharacteristicUUID:
                    requestCharacteristic = characteristic
                case Self.challengeCharacteristicUUID:
                    challengeCharacteristic = characteristic
                    peripheral.setNotifyValue(true, for: characteristic)
                case Self.assertionCharacteristicUUID:
                    assertionCharacteristic = characteristic
                case Self.resultCharacteristicUUID:
                    resultCharacteristic = characteristic
                    peripheral.setNotifyValue(true, for: characteristic)
                default:
                    continue
                }
            }

            guard let requestCharacteristic, challengeCharacteristic != nil, assertionCharacteristic != nil else {
                record(error: BluetoothUnlockError.characteristicMissing("request/challenge/assertion"))
                return
            }

            peripheral.writeValue(Data([0x01]), for: requestCharacteristic, type: .withResponse)
            return
        }
        record(error: BluetoothUnlockError.connectionFailed(error.localizedDescription))
    }

    func peripheral(
        _ peripheral: CBPeripheral,
        didUpdateValueFor characteristic: CBCharacteristic,
        error: Error?
    ) {
        guard let error else {
            guard characteristic.uuid == Self.challengeCharacteristicUUID,
                  let value = characteristic.value else {
                return
            }

            do {
                let challenge = try UnlockProtocol.decodeChallenge(from: value)
                guard challenge.version == 1 else {
                    throw BluetoothUnlockError.receivedInvalidChallenge("协议版本不是 1。")
                }
                guard challenge.audience == "windows-unlock" else {
                    throw BluetoothUnlockError.receivedInvalidChallenge("audience 不匹配。")
                }
                guard challenge.nonce.count == 32 else {
                    throw BluetoothUnlockError.receivedInvalidChallenge("nonce 不是 32 字节。")
                }

                let assertion = try UnlockProtocol.sign(challenge: challenge, using: keyStore)
                let assertionData = try UnlockProtocol.encode(assertion: assertion)
                guard let assertionCharacteristic else {
                    throw BluetoothUnlockError.characteristicMissing("assertion")
                }
                peripheral.writeValue(assertionData, for: assertionCharacteristic, type: .withResponse)
            } catch {
                record(error: error)
            }
            return
        }
        record(error: BluetoothUnlockError.connectionFailed(error.localizedDescription))
    }

    func peripheral(
        _ peripheral: CBPeripheral,
        didWriteValueFor characteristic: CBCharacteristic,
        error: Error?
    ) {
        guard let error else {
            return
        }
        record(error: BluetoothUnlockError.writeFailed(error.localizedDescription))
    }

    func peripheral(
        _ peripheral: CBPeripheral,
        didUpdateNotificationStateFor characteristic: CBCharacteristic,
        error: Error?
    ) {
        if let error {
            record(error: BluetoothUnlockError.connectionFailed(error.localizedDescription))
            return
        }
        guard characteristic.isNotifying else {
            record(error: BluetoothUnlockError.connectionFailed("Windows challenge characteristic 没有成功订阅。"))
            return
        }
    }

    private func record(error: Error) {
        lastError = error.localizedDescription
        onError?(lastError ?? "系统没有提供详细错误。")
    }

    private func clearConnectionState() {
        requestCharacteristic = nil
        challengeCharacteristic = nil
        assertionCharacteristic = nil
        resultCharacteristic = nil
    }
}
