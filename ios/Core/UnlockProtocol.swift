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
    let signatureRawRepresentation: Data
}

enum UnlockProtocol {
    static let signatureContext = Data("unlock-windows-with-iphone/v1".utf8)

    static func encode(challenge: UnlockChallenge) throws -> Data {
        do {
            let encoder = JSONEncoder()
            encoder.outputFormatting = [.sortedKeys]
            return try encoder.encode(challenge)
        } catch {
            throw UnlockError.protocolEncodingFailed("编码 challenge 失败：\(error.localizedDescription)")
        }
    }

    static func decodeChallenge(from data: Data) throws -> UnlockChallenge {
        do {
            return try JSONDecoder().decode(UnlockChallenge.self, from: data)
        } catch {
            throw UnlockError.protocolEncodingFailed("解析 challenge 失败：\(error.localizedDescription)")
        }
    }

    static func encode(assertion: UnlockAssertion) throws -> Data {
        do {
            let encoder = JSONEncoder()
            encoder.outputFormatting = [.sortedKeys]
            return try encoder.encode(assertion)
        } catch {
            throw UnlockError.protocolEncodingFailed("编码 assertion 失败：\(error.localizedDescription)")
        }
    }

    static func bytesToSign(for challenge: UnlockChallenge) throws -> Data {
        guard challenge.version == 1 else {
            throw UnlockError.protocolEncodingFailed("不支持的协议版本：\(challenge.version)")
        }
        guard challenge.nonce.count == 32 else {
            throw UnlockError.protocolEncodingFailed("nonce 必须是 32 字节。")
        }

        var bytes = signatureContext
        bytes.append(0)

        var version = UInt32(challenge.version).bigEndian
        withUnsafeBytes(of: &version) {
            bytes.append(contentsOf: $0)
        }

        var requestID = challenge.requestID.uuid
        withUnsafeBytes(of: &requestID) {
            bytes.append(contentsOf: $0)
        }

        bytes.append(contentsOf: challenge.nonce)

        var issuedAtMilliseconds = UInt64(bitPattern: challenge.issuedAtMilliseconds).bigEndian
        withUnsafeBytes(of: &issuedAtMilliseconds) {
            bytes.append(contentsOf: $0)
        }

        let audience = Data(challenge.audience.utf8)
        guard audience.count <= UInt16.max else {
            throw UnlockError.protocolEncodingFailed("audience 不能超过 UInt16 长度。")
        }

        var audienceLength = UInt16(audience.count).bigEndian
        withUnsafeBytes(of: &audienceLength) {
            bytes.append(contentsOf: $0)
        }
        bytes.append(contentsOf: audience)

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
            signatureRawRepresentation: signature
        )
    }

    static func fingerprint(for publicKey: Data) -> String {
        SHA256.hash(data: publicKey)
            .map { String(format: "%02x", $0) }
            .joined()
    }
}
