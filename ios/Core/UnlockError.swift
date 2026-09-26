import Foundation

enum UnlockError: LocalizedError, Equatable {
    case secureEnclaveUnavailable
    case accessControlCreationFailed(String)
    case keychainFailure(operation: String, status: OSStatus)
    case storedKeyUnreadable(String)
    case keyGenerationFailed(String)
    case signingFailed(String)
    case localVerificationFailed

    var errorDescription: String? {
        switch self {
        case .secureEnclaveUnavailable:
            return "Secure Enclave 不可用。请使用实体 iPhone；本项目不会退回软件密钥。"
        case let .accessControlCreationFailed(message):
            return "创建 Secure Enclave 访问控制失败：\(message)"
        case let .keychainFailure(operation, status):
            return "Keychain 操作“\(operation)”失败，OSStatus=\(status)。"
        case let .storedKeyUnreadable(message):
            return "Keychain 中已有密钥，但无法恢复为 Secure Enclave 私钥：\(message)"
        case let .keyGenerationFailed(message):
            return "生成 Secure Enclave 私钥失败：\(message)"
        case let .signingFailed(message):
            return "Secure Enclave 签名失败：\(message)"
        case .localVerificationFailed:
            return "本地公钥验证失败；不会把这次结果报告为认证成功。"
        }
    }
}
