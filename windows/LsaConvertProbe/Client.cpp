// Created by Rui MA on 29 Sep 2026

#include "Protocol.h"

#define WIN32_NO_STATUS
#include <Windows.h>
#undef WIN32_NO_STATUS

#include <ntsecapi.h>
#include <ntstatus.h>

#include <cstring>
#include <iomanip>
#include <iostream>
#include <string_view>

namespace {

class LsaHandle final {
public:
    explicit LsaHandle(LSA_HANDLE value = nullptr) noexcept : value_(value) {}
    LsaHandle(const LsaHandle&) = delete;
    LsaHandle& operator=(const LsaHandle&) = delete;
    ~LsaHandle() {
        if (value_ != nullptr) {
            LsaDeregisterLogonProcess(value_);
        }
    }
    [[nodiscard]] LSA_HANDLE get() const noexcept { return value_; }

private:
    LSA_HANDLE value_;
};

class LsaBuffer final {
public:
    explicit LsaBuffer(PVOID value = nullptr) noexcept : value_(value) {}
    LsaBuffer(const LsaBuffer&) = delete;
    LsaBuffer& operator=(const LsaBuffer&) = delete;
    ~LsaBuffer() {
        if (value_ != nullptr) {
            LsaFreeReturnBuffer(value_);
        }
    }
    [[nodiscard]] PVOID get() const noexcept { return value_; }

private:
    PVOID value_;
};

void printStatus(const char* operation, const NTSTATUS status) {
    std::cerr << operation << " failed: status=0x" << std::hex << std::setw(8)
              << std::setfill('0') << static_cast<unsigned long>(status)
              << " win32=" << std::dec << LsaNtStatusToWinError(status) << "\n";
}

} // namespace

int wmain() {
    LSA_STRING processName{};
    char processNameBuffer[] = "UWIConvertProbe";
    processName.Buffer = processNameBuffer;
    processName.Length = static_cast<USHORT>(std::strlen(processNameBuffer));
    processName.MaximumLength = processName.Length;

    LSA_OPERATIONAL_MODE mode = 0;
    LSA_HANDLE rawLsa = nullptr;
    const NTSTATUS registerStatus = LsaRegisterLogonProcess(
        &processName,
        &rawLsa,
        &mode
    );
    if (registerStatus < 0) {
        printStatus("LsaRegisterLogonProcess", registerStatus);
        std::cerr << "Run this client as LocalSystem with SeTcbPrivilege enabled.\n";
        return 2;
    }
    const LsaHandle lsa(rawLsa);

    LSA_STRING packageName{};
    packageName.Buffer = const_cast<PCHAR>(
        unlock_windows::lsa_convert_probe::kPackageName
    );
    packageName.Length = static_cast<USHORT>(
        std::char_traits<char>::length(packageName.Buffer)
    );
    packageName.MaximumLength = packageName.Length;

    ULONG packageId = 0;
    const NTSTATUS lookupStatus = LsaLookupAuthenticationPackage(
        lsa.get(),
        &packageName,
        &packageId
    );
    if (lookupStatus < 0) {
        printStatus("LsaLookupAuthenticationPackage", lookupStatus);
        std::cerr << "The diagnostic SSP/AP is not loaded by LSA.\n";
        return 3;
    }

    unlock_windows::lsa_convert_probe::Request request{};
    PVOID rawReport = nullptr;
    ULONG reportBytes = 0;
    NTSTATUS protocolStatus = STATUS_UNSUCCESSFUL;
    const NTSTATUS callStatus = LsaCallAuthenticationPackage(
        lsa.get(),
        packageId,
        &request,
        sizeof(request),
        &rawReport,
        &reportBytes,
        &protocolStatus
    );
    const LsaBuffer report(rawReport);
    if (callStatus < 0) {
        printStatus("LsaCallAuthenticationPackage", callStatus);
        return 4;
    }
    if (rawReport == nullptr || reportBytes < sizeof(wchar_t) ||
        reportBytes % sizeof(wchar_t) != 0 ||
        reportBytes > unlock_windows::lsa_convert_probe::kMaximumReportBytes) {
        std::cerr << "The package returned an invalid report buffer.\n";
        return 5;
    }

    const auto* text = static_cast<const wchar_t*>(rawReport);
    const std::size_t characterCount = reportBytes / sizeof(wchar_t);
    if (text[characterCount - 1] != L'\0') {
        std::cerr << "The package report is not null-terminated.\n";
        return 5;
    }
    std::wcout << std::wstring_view(text, characterCount - 1);
    if (protocolStatus < 0) {
        printStatus("diagnostic protocol", protocolStatus);
        return 6;
    }
    return 0;
}
