import CryptoKit
import Foundation

struct UnlockChallenge: Codable, Equatable, Sendable {
    let version: Int
    let requestID: UUID
    let nonce: Data
    let issuedAtMilliseconds: Int64
    let audience: String

    static func new(audience: String, now: Date = Date()) -> UnlockChallenge {
        let nonce = Data((0..<32).map { _ in UInt8.random(in: UInt8.min...UInt8.max) })
        return UnlockChallenge(
            version: 1,
            requestID: UUID(),
            nonce: nonce,
            issuedAtMilliseconds: Int64(now.timeIntervalSince1970 * 1_000),
            audience: audience
        )
    }
}

struct UnlockAssertion: Codable, Equatable, Sendable {
    let version: Int
    let requestID: UUID
    let keyID: String
    let publicKeyRawRepresentation: Data
    let signatureDERRepresentation: Data
}

enum UnlockProtocol {
    static let signatureContext = Data("unlock-windows-with-iphone/v1".utf8)

    static func canonicalJSON(for challenge: UnlockChallenge) throws -> Data {
        let encoder = JSONEncoder()
        encoder.outputFormatting = [.sortedKeys]
        return try encoder.encode(challenge)
    }

    static func bytesToSign(for challenge: UnlockChallenge) throws -> Data {
        var bytes = signatureContext
        bytes.append(0)
        bytes.append(contentsOf: try canonicalJSON(for: challenge))
        return bytes
    }

    static func sign(
        challenge: UnlockChallenge,
        using keyStore: SecureEnclaveKeyStore
    ) throws -> UnlockAssertion {
        let payload = try bytesToSign(for: challenge)
        let publicKey = try keyStore.publicKeyRawRepresentation()
        let signature = try keyStore.sign(data: payload)

        return UnlockAssertion(
            version: challenge.version,
            requestID: challenge.requestID,
            keyID: fingerprint(for: publicKey),
            publicKeyRawRepresentation: publicKey,
            signatureDERRepresentation: signature
        )
    }

    static func fingerprint(for publicKey: Data) -> String {
        SHA256.hash(data: publicKey)
            .map { String(format: "%02x", $0) }
            .joined()
    }
}
