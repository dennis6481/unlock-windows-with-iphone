// Created by Rui MA on 27 Sep 2026

#include "UnlockCredentialApprovalClient.h"

#include "UnlockServiceIpc.h"
#include "UnlockLogonBufferCodec.h"

#include <Windows.h>
#include <ntsecapi.h>

#include <cstring>

namespace unlock_windows::credential_provider {

ApprovalFetchResult consumePendingApproval() noexcept {
    try {
        const auto response = service::ipc::call(
            service::ipc::Operation::consumeUnlockApproval,
            {}
        );
        if (response.status != service::ipc::Status::success) {
            return {ApprovalFetchCode::unavailable, {}};
        }
        if (response.payload.size() != sizeof(protocol::UnlockLogonBuffer)) {
            return {ApprovalFetchCode::invalid_response, {}};
        }

        protocol::UnlockLogonBuffer buffer{};
        std::memcpy(&buffer, response.payload.data(), sizeof(buffer));
        const auto validation = protocol::validateUnlockLogonBuffer(
            std::span<const std::uint8_t>(
                reinterpret_cast<const std::uint8_t*>(&buffer),
                sizeof(buffer)
            )
        );
        if (!validation.succeeded()) {
            return {ApprovalFetchCode::invalid_response, {}};
        }
        return {ApprovalFetchCode::approved, buffer};
    } catch (...) {
        return {ApprovalFetchCode::unavailable, {}};
    }
}

AuthenticationPackageResult lookupAuthenticationPackage() noexcept {
    LSA_HANDLE lsa = nullptr;
    if (LsaConnectUntrusted(&lsa) < 0) {
        return {AuthenticationPackageCode::unavailable, 0};
    }

    LSA_STRING packageName{};
    packageName.Buffer = const_cast<PCHAR>(
        protocol::kUnlockLsaAuthenticationPackageName
    );
    packageName.Length = static_cast<USHORT>(std::strlen(packageName.Buffer));
    packageName.MaximumLength = packageName.Length;

    ULONG identifier = 0;
    const auto status = LsaLookupAuthenticationPackage(
        lsa,
        &packageName,
        &identifier
    );
    LsaDeregisterLogonProcess(lsa);
    if (status < 0) {
        return {AuthenticationPackageCode::unavailable, 0};
    }
    return {AuthenticationPackageCode::available, identifier};
}

} // namespace unlock_windows::credential_provider
