// Created by Rui MA on 26 Sep 2026

import CryptoKit
import Foundation
import Observation
import UIKit

@MainActor
@Observable
final class UnlockSetupModel {
    static let shared = UnlockSetupModel()
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
    var publicKeyCopyStatus: String?
    var lastError: String?
    var lastTestResult: String?
    var bluetoothStatus = "未启动"
    var bluetoothError: String?
    var automaticEnabled = false
    var rssiThreshold = -60.0
    var currentRSSI: Int?
    var targetIdentifier: String?
    var bluetoothDiagnostics: [String] = []

    private let keyStore: SecureEnclaveKeyStore
    private let bluetoothAuthenticator: BluetoothAuthenticator

    init(keyStore: SecureEnclaveKeyStore = SecureEnclaveKeyStore()) {
        self.keyStore = keyStore
        self.bluetoothAuthenticator = BluetoothAuthenticator(keyStore: keyStore)
        automaticEnabled = bluetoothAuthenticator.automaticEnabled
        rssiThreshold = Double(bluetoothAuthenticator.threshold)
        targetIdentifier = bluetoothAuthenticator.targetIdentifier?.uuidString
        self.bluetoothAuthenticator.onStatus = { [weak self] status in self?.bluetoothStatus = status }
        self.bluetoothAuthenticator.onRSSI = { [weak self] value in self?.currentRSSI = value }
        self.bluetoothAuthenticator.onTarget = { [weak self] identifier in self?.targetIdentifier = identifier.uuidString }
        self.bluetoothAuthenticator.onDiagnostic = { [weak self] event in
            guard let self else { return }
            self.bluetoothDiagnostics.append(event)
            if self.bluetoothDiagnostics.count > 64 { self.bluetoothDiagnostics.removeFirst() }
        }
        self.bluetoothAuthenticator.onError = { [weak self] message in
            self?.bluetoothStatus = "连接失败"
            self?.bluetoothError = message
        }
        self.bluetoothAuthenticator.onResult = { [weak self] result in
            self?.bluetoothStatus = "Windows 返回：\(result)"
            if result == "unlock_approved" || result == "enrollment_saved" || result == "enrollment_already_registered" {
                self?.bluetoothError = nil
            } else {
                self?.bluetoothError = "Windows 返回：\(result)"
            }
        }
        bluetoothAuthenticator.activate()
    }

    func setAutomaticEnabled(_ enabled: Bool) {
        automaticEnabled = enabled
        bluetoothError = nil
        bluetoothAuthenticator.setAutomaticEnabled(enabled)
    }

    func setRSSIThreshold(_ value: Double) {
        rssiThreshold = value.rounded()
        bluetoothAuthenticator.setThreshold(Int(rssiThreshold))
    }

    func setForeground(_ active: Bool) {
        bluetoothAuthenticator.setForeground(active)
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

    func copyPublicKey() {
        lastError = nil
        publicKeyCopyStatus = nil

        do {
            UIPasteboard.general.string = try keyStore.publicKeyHexRepresentation()
            publicKeyCopyStatus = "原始公钥已复制，可在 Windows PairingTool 中读取。"
        } catch {
            lastError = error.localizedDescription
        }
    }

    func startBluetooth() {
        bluetoothError = nil
        do {
            try bluetoothAuthenticator.start()

        } catch {
            bluetoothStatus = "连接失败"
            bluetoothError = error.localizedDescription
        }
    }

    func startEnrollment() {
        bluetoothError = nil
        do {
            try bluetoothAuthenticator.startEnrollment()

        } catch {
            bluetoothStatus = "登记失败"
            bluetoothError = error.localizedDescription
        }
    }

    func stopBluetooth() {
        setAutomaticEnabled(false)
        bluetoothAuthenticator.stop()
    }
}
