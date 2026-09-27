// Created by Rui MA on 27 Sep 2026

#define WIN32_NO_STATUS
#include <Windows.h>
#undef WIN32_NO_STATUS

#include <ntsecapi.h>
#include <ntstatus.h>

#include "UnlockLogonBuffer.h"

#include <iostream>

int main() {
    LSA_HANDLE lsa = nullptr;
    const auto connectStatus = LsaConnectUntrusted(&lsa);
    if (connectStatus < 0) {
        std::cerr << "LsaConnectUntrusted failed: 0x" << std::hex
                  << static_cast<unsigned long>(connectStatus) << "\n";
        return 2;
    }

    LSA_STRING packageName{};
    packageName.Buffer = const_cast<PCHAR>(
        unlock_windows::protocol::kUnlockLsaAuthenticationPackageName
    );
    packageName.Length = static_cast<USHORT>(
        std::char_traits<char>::length(packageName.Buffer)
    );
    packageName.MaximumLength = packageName.Length;

    ULONG packageId = 0;
    const auto lookupStatus = LsaLookupAuthenticationPackage(
        lsa,
        &packageName,
        &packageId
    );
    LsaDeregisterLogonProcess(lsa);

    if (lookupStatus < 0) {
        std::cerr << "UnlockWindowsWithIPhone is not loaded by LSA: 0x"
                  << std::hex << static_cast<unsigned long>(lookupStatus)
                  << "\n";
        return 3;
    }

    std::cout << "UnlockWindowsWithIPhone is loaded by LSA; package id="
              << std::dec << packageId << "\n";
    return 0;
}
