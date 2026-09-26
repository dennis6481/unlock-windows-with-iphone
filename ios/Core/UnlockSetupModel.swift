import CryptoKit
import Foundation
import Observation

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

    private let keyStore: SecureEnclaveKeyStore

    init(keyStore: SecureEnclaveKeyStore = SecureEnclaveKeyStore()) {
        self.keyStore = keyStore
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
            let publicKey = try P256.Signing.PublicKey(rawRepresentation: assertion.publicKeyRawRepresentation)
            let signature = try P256.Signing.ECDSASignature(derRepresentation: assertion.signatureDERRepresentation)
            let payload = try UnlockProtocol.bytesToSign(for: challenge)

            guard publicKey.isValidSignature(signature, for: payload) else {
                throw UnlockError.localVerificationFailed
            }

            lastTestResult = "本地签名和公钥验证成功；DER 签名长度：\(assertion.signatureDERRepresentation.count) 字节。"
            state = .ready
        } catch {
            state = .error
            lastError = error.localizedDescription
        }
    }
}
