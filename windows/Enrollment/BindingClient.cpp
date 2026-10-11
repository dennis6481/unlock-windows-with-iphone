// Created by Rui MA on 11 Oct 2026

#include "BindingClient.h"
#include "EnrollmentSession.h"
#include <shellapi.h>
#include <objbase.h>

namespace unlock_windows::enrollment {
using namespace saved_credential;

winrt::handle createCancellation(const std::wstring& sid, std::wstring& name) {
    GUID id{};
    winrt::check_hresult(CoCreateGuid(&id));
    name = kBindingCancelPrefix + std::wstring(winrt::to_hstring(winrt::guid{id}));
    PSECURITY_DESCRIPTOR descriptor = nullptr;
    const auto sddl = L"D:P(A;;GA;;;SY)(A;;GA;;;" + sid + L")";
    winrt::check_bool(ConvertStringSecurityDescriptorToSecurityDescriptorW(sddl.c_str(), SDDL_REVISION_1, &descriptor, nullptr));
    SECURITY_ATTRIBUTES attributes{sizeof(attributes), descriptor, FALSE};
    winrt::handle event(CreateEventW(&attributes, TRUE, FALSE, name.c_str()));
    const auto error = GetLastError(); LocalFree(descriptor);
    if (!event || error == ERROR_ALREADY_EXISTS) throw winrt::hresult_error(HRESULT_FROM_WIN32(error ? error : ERROR_INVALID_HANDLE));
    return event;
}

BindingSummary readBinding() {
    Packet response;
    CallDiagnostics diagnostics;
    if (!call(Operation::bindingStatus, SensitiveBytes{}, response, 2000, &diagnostics))
        throw std::runtime_error("Binding status IPC failed (Win32 " + std::to_string(diagnostics.win32Error) + ")");
    if (response.result == Result::rejected)
        throw BindingStatusRejected("Binding status query rejected by the service");
    BindingSummary summary;
    if (response.result == Result::internalError && !response.payload.value.empty())
        throw std::runtime_error(std::string(response.payload.value.begin(), response.payload.value.end()));
    if (response.result != Result::success || !decodeBindingSummary(response.payload.value.data(), response.payload.value.size(), summary))
        throw std::runtime_error("Binding status could not be read or the target account was rejected");
    return summary;
}

DWORD launchHelper(const std::wstring& arguments, bool elevated, const std::function<void()>& update) {
    std::wstring executable(32768, L'\0');
    const auto length = GetModuleFileNameW(nullptr, executable.data(), static_cast<DWORD>(executable.size()));
    require(length && length < executable.size(), "Locate desktop helper");
    executable.resize(length);
    SHELLEXECUTEINFOW launch{sizeof(launch)};
    launch.fMask = SEE_MASK_NOCLOSEPROCESS | SEE_MASK_NOASYNC | SEE_MASK_FLAG_NO_UI;
    launch.lpVerb = elevated ? L"runas" : L"open";
    launch.lpFile = executable.c_str();
    launch.lpParameters = arguments.c_str();
    launch.nShow = SW_SHOWNORMAL;
    if (!ShellExecuteExW(&launch)) throw winrt::hresult_error(HRESULT_FROM_WIN32(GetLastError()));
    Handle process;
    process.value = launch.hProcess;
    require(process.value != nullptr, "Desktop helper process handle");
    for (;;) {
        const auto wait = WaitForSingleObject(process.value, update ? 1000 : INFINITE);
        if (wait == WAIT_OBJECT_0) break;
        require(wait == WAIT_TIMEOUT, "Wait for desktop helper");
        update();
    }
    DWORD code = 0;
    require(GetExitCodeProcess(process.value, &code), "Desktop helper result");
    return code;
}

void manageBinding(Operation operation, const SensitiveBytes& payload) {
    std::wstring hex;
    constexpr wchar_t alphabet[] = L"0123456789abcdef";
    for (const auto value : payload.value) { hex += alphabet[value >> 4]; hex += alphabet[value & 15]; }
    const auto code = launchHelper(L"--binding-helper " + std::to_wstring(static_cast<unsigned>(operation)) + L" " + hex, true);
    if (code == static_cast<DWORD>(Result::busy)) throw std::runtime_error("The service is still finishing a Bluetooth task. Try again.");
    if (code != 0) throw std::runtime_error("Binding management did not return success. Check the current binding status.");
}

int runBindingHelper(std::wstring_view operation, std::wstring_view hex) {
    if (!elevatedAdmin()) throw std::runtime_error("Binding management requires UAC elevation");
    const auto op = static_cast<Operation>(std::stoul(std::wstring(operation)));
    if (op != Operation::beginBinding && op != Operation::removeBinding && op != Operation::saveThreshold)
        throw std::invalid_argument("Invalid binding management operation");
    if (hex.empty() || hex.size() % 2 || hex.size() > 2 * kMaxPacket) throw std::invalid_argument("Invalid binding payload size");
    SensitiveBytes bytes;
    auto digit = [](wchar_t ch) -> unsigned {
        if (ch >= L'0' && ch <= L'9') return ch - L'0';
        if (ch >= L'a' && ch <= L'f') return ch - L'a' + 10;
        throw std::invalid_argument("Invalid binding payload encoding");
    };
    for (std::size_t index = 0; index < hex.size(); index += 2)
        bytes.value.push_back(static_cast<std::uint8_t>((digit(hex[index]) << 4) | digit(hex[index + 1])));
    Packet response;
    CallDiagnostics diagnostics;
    if (!call(op, std::move(bytes), response, 2000, &diagnostics))
        throw std::runtime_error("Binding management IPC failed (Win32 " + std::to_string(diagnostics.win32Error) + ")");
    if (response.result == Result::internalError && !response.payload.value.empty())
        throw std::runtime_error(std::string(response.payload.value.begin(), response.payload.value.end()));
    return static_cast<int>(response.result);
}
}
