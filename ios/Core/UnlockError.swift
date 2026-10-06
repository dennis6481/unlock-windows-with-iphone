// Created by Rui MA on 26 Sep 2026

import Foundation

enum UnlockError: LocalizedError, Equatable {
    case secureEnclaveUnavailable
    case accessControlCreationFailed(String)
    case keychainFailure(operation: String, status: OSStatus)
    case storedKeyUnreadable(String)
    case keyGenerationFailed(String)
    case signingFailed(String)
    case protocolEncodingFailed(String)

    var errorDescription: String? {
        switch self {
        case .secureEnclaveUnavailable:
            return String(localized: "Secure Enclave is unavailable. Use a physical iPhone; software keys are not supported.")
        case let .accessControlCreationFailed(message):
            return String(localized: "Could not create Secure Enclave access control: \(message)")
        case let .keychainFailure(operation, status):
            return String(localized: "Keychain operation “\(operation)” failed, OSStatus=\(status).")
        case let .storedKeyUnreadable(message):
            return String(localized: "Could not restore the stored Secure Enclave key: \(message)")
        case let .keyGenerationFailed(message):
            return String(localized: "Could not generate the Secure Enclave key: \(message)")
        case let .signingFailed(message):
            return String(localized: "Secure Enclave signing failed: \(message)")
        case let .protocolEncodingFailed(message):
            return String(localized: "Authentication protocol encoding failed: \(message)")
        }
    }
}
