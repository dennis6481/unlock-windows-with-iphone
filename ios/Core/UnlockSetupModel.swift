// Modified by Rui MA on 26 Sep 2026

@preconcurrency import AccessorySetupKit
import CoreBluetooth
import CryptoKit
import Foundation
import Observation
import UIKit

@MainActor
@Observable
final class UnlockSetupModel {
    enum State: Equatable {
        case idle
        case checking
        case ready
        case error

        var title: String {
            switch self {
            case .idle:
                return "尚未检查"
            case .checking:
                return "检查中"
            case .ready:
                return "密钥已就绪"
            case .error:
                return "发生错误"
            }
        }
    }

    var state: State = .idle
    var publicKeyFingerprint: String?
    var lastError: String?
    var lastTestResult: String?
    var bluetoothStatus = "未启动"
    var bluetoothError: String?

    private let keyStore: SecureEnclaveKeyStore
    private let bluetoothAuthenticator: BluetoothAuthenticator
    private let accessorySession: ASAccessorySession

    init(keyStore: SecureEnclaveKeyStore = SecureEnclaveKeyStore()) {
        self.keyStore = keyStore
        self.bluetoothAuthenticator = BluetoothAuthenticator(keyStore: keyStore)
        self.accessorySession = ASAccessorySession()
        self.bluetoothAuthenticator.onError = { [weak self] message in
            self?.bluetoothStatus = "连接失败"
            self?.bluetoothError = message
        }
        accessorySession.activate(on: .main) { [weak self] event in
            Task { @MainActor [weak self] in
                self?.handleAccessoryEvent(event)
            }
        }
    }

    func prepareKey() {
        state = .checking
        lastError = nil

        do {
            let publicKey = try keyStore.publicKeyRawRepresentation()
            publicKeyFingerprint = UnlockProtocol.fingerprint(for: publicKey)
            state = .ready
        } catch {
            state = .error
            lastError = error.localizedDescription
        }
    }

    func signTestChallenge() {
        lastError = nil
        lastTestResult = nil

        do {
            let challenge = UnlockChallenge.new(audience: "windows-unlock")
            let assertion = try UnlockProtocol.sign(challenge: challenge, using: keyStore)
            let publicKey = try P256.Signing.PublicKey(x963Representation: assertion.publicKeyRawRepresentation)
            let signature = try P256.Signing.ECDSASignature(rawRepresentation: assertion.signatureRawRepresentation)
            let payload = try UnlockProtocol.bytesToSign(for: challenge)

            guard publicKey.isValidSignature(signature, for: payload) else {
                throw UnlockError.localVerificationFailed
            }

            lastTestResult = "本地签名和公钥验证成功；raw r||s 签名长度：\(assertion.signatureRawRepresentation.count) 字节。"
            state = .ready
        } catch {
            state = .error
            lastError = error.localizedDescription
        }
    }

    func startBluetooth() {
        bluetoothError = nil
        showAccessoryPicker()
    }

    private func showAccessoryPicker() {
        var descriptor = ASDiscoveryDescriptor()
        descriptor.bluetoothServiceUUID = BluetoothAuthenticator.serviceUUID

        guard let productImage = UIImage(systemName: "desktopcomputer") else {
            bluetoothStatus = "Connection failed"
            bluetoothError = "Could not create the Windows device icon."
            return
        }

        let displayItem = ASPickerDisplayItem(
            name: "Windows PC",
            productImage: productImage,
            descriptor: descriptor
        )
        bluetoothStatus = "Choose the Windows PC in the system picker"
        accessorySession.showPicker(for: [displayItem]) { [weak self] error in
            guard let error else { return }
            Task { @MainActor [weak self] in
                self?.bluetoothStatus = "Connection failed"
                self?.bluetoothError = error.localizedDescription
            }
        }
    }

    private func handleAccessoryEvent(_ event: ASAccessoryEvent) {
        switch event.eventType {
        case .accessoryAdded:
            guard let bluetoothIdentifier = event.accessory?.bluetoothIdentifier else {
                bluetoothStatus = "Connection failed"
                bluetoothError = "AccessorySetupKit did not return a Bluetooth identifier."
                return
            }

            do {
                try bluetoothAuthenticator.start(accessoryIdentifier: bluetoothIdentifier)
                bluetoothStatus = "Connecting to the authorized Windows GATT host"
            } catch {
                bluetoothStatus = "Connection failed"
                bluetoothError = error.localizedDescription
            }
        case .pickerDidPresent:
            bluetoothStatus = "Choose the Windows PC in the system picker"
        default:
            break
        }
    }

    func stopBluetooth() {
        bluetoothAuthenticator.stop()
        bluetoothStatus = "已停止"
    }
}
