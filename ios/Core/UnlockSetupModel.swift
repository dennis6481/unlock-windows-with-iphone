// Created by Rui MA on 26 Sep 2026

import Foundation
import Observation

@MainActor
@Observable
final class UnlockSetupModel {
    static let shared = UnlockSetupModel()
    private(set) var bluetooth = BluetoothViewState()
    private(set) var publicKeyFingerprint: String?
    private(set) var keyError: String?
    private(set) var bluetoothDiagnostics: [String] = []
    private let authenticator: BluetoothAuthenticator

    init(keyStore: SecureEnclaveKeyStore = SecureEnclaveKeyStore()) {
        authenticator = BluetoothAuthenticator(keyStore: keyStore)
        authenticator.onUpdate = { [weak self] state in self?.bluetooth = state }
        authenticator.onDiagnostic = { [weak self] event in
            guard let self else { return }
            self.bluetoothDiagnostics.append(event)
            if self.bluetoothDiagnostics.count > 64 { self.bluetoothDiagnostics.removeFirst() }
        }
        do { publicKeyFingerprint = UnlockProtocol.fingerprint(for: try keyStore.publicKeyRawRepresentation()) }
        catch { keyError = error.localizedDescription }
        authenticator.activate()
    }

    func setForeground(_ active: Bool) { authenticator.setForeground(active) }
    func setAutomaticEnabled(_ enabled: Bool) { authenticator.setAutomaticEnabled(enabled) }
    func setRSSIThreshold(_ value: Double) { authenticator.setThreshold(Int(value.rounded())) }
    func retryConnection() { authenticator.retryConnection() }
    func startEnrollment() { authenticator.startEnrollment() }
    func cancelEnrollment() { authenticator.cancelEnrollment() }
}
