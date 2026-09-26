import CryptoKit
import Foundation
import Security

final class SecureEnclaveKeyStore {
    private let keychainService = "com.example.unlock-windows-with-iphone"
    private let keychainAccount = "iphone-unlock-signing-key-v1"

    func loadOrCreateKey() throws -> SecureEnclave.P256.Signing.PrivateKey {
        guard SecureEnclave.isAvailable else {
            throw UnlockError.secureEnclaveUnavailable
        }

        if let serializedKey = try loadSerializedKey() {
            do {
                return try SecureEnclave.P256.Signing.PrivateKey(dataRepresentation: serializedKey)
            } catch {
                throw UnlockError.storedKeyUnreadable(error.localizedDescription)
            }
        }

        let accessControl = try makeAccessControl()

        do {
            let privateKey = try SecureEnclave.P256.Signing.PrivateKey(accessControl: accessControl)
            try store(serializedKey: privateKey.dataRepresentation)
            return privateKey
        } catch let error as UnlockError {
            throw error
        } catch {
            throw UnlockError.keyGenerationFailed(error.localizedDescription)
        }
    }

    func publicKeyRawRepresentation() throws -> Data {
        let privateKey = try loadOrCreateKey()
        return privateKey.publicKey.rawRepresentation
    }

    func sign(data: Data) throws -> Data {
        let privateKey = try loadOrCreateKey()

        do {
            let signature = try privateKey.signature(for: data)
            return signature.derRepresentation
        } catch {
            throw UnlockError.signingFailed(error.localizedDescription)
        }
    }

    private func makeAccessControl() throws -> SecAccessControl {
        var creationError: Unmanaged<CFError>?
        guard let accessControl = SecAccessControlCreateWithFlags(
            nil,
            kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly,
            [.privateKeyUsage],
            &creationError
        ) else {
            let message = creationError?.takeRetainedValue().localizedDescription ?? "系统没有提供详细错误。"
            throw UnlockError.accessControlCreationFailed(message)
        }

        return accessControl
    }

    private func baseQuery() -> [String: Any] {
        [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: keychainService,
            kSecAttrAccount as String: keychainAccount
        ]
    }

    private func loadSerializedKey() throws -> Data? {
        var query = baseQuery()
        query[kSecReturnData as String] = true
        query[kSecMatchLimit as String] = kSecMatchLimitOne

        var result: CFTypeRef?
        let status = SecItemCopyMatching(query as CFDictionary, &result)

        switch status {
        case errSecSuccess:
            guard let data = result as? Data else {
                throw UnlockError.keychainFailure(operation: "读取密钥数据类型", status: errSecInternalError)
            }
            return data
        case errSecItemNotFound:
            return nil
        default:
            throw UnlockError.keychainFailure(operation: "读取签名密钥", status: status)
        }
    }

    private func store(serializedKey: Data) throws {
        var item = baseQuery()
        item[kSecValueData as String] = serializedKey
        item[kSecAttrAccessible as String] = kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly
        item[kSecAttrSynchronizable as String] = false

        let status = SecItemAdd(item as CFDictionary, nil)
        guard status == errSecSuccess else {
            throw UnlockError.keychainFailure(operation: "保存签名密钥", status: status)
        }
    }
}
