// Created by Rui MA on 26 Sep 2026


#include "EnrollmentStore.h"
#include "SavedCredentialIpc.h"

#include <Windows.h>
#include <propvarutil.h>
#include <propkey.h>
#include <shobjidl.h>

#include <winrt/Windows.Data.Xml.Dom.h>
#include <winrt/Windows.Foundation.h>
#include <winrt/Windows.UI.Notifications.h>
#include <winrt/base.h>

#include <condition_variable>
#include <cctype>
#include <chrono>
#include <filesystem>
#include <iostream>
#include <mutex>
#include <stdexcept>
#include <string>
#include <string_view>
#include <vector>

namespace {

using namespace winrt;
using namespace winrt::Windows::Data::Xml::Dom;
using namespace winrt::Windows::UI::Notifications;

constexpr wchar_t kAppUserModelId[] = L"RuiMA.UnlockWindowsWithIPhone.PairingTool";

void printUsage() {
    std::cout << "Usage:\n"
              << "  unlock_pairing_tool.exe --key-hex <130-hex-digit-key> [--replace]\n"
              << "  unlock_pairing_tool.exe --key-clipboard [--replace]\n"
              << "  unlock_pairing_tool.exe --clear\n";
}

std::uint8_t hexDigit(const char value) {
    if (value >= '0' && value <= '9') return static_cast<std::uint8_t>(value - '0');
    if (value >= 'a' && value <= 'f') return static_cast<std::uint8_t>(value - 'a' + 10);
    if (value >= 'A' && value <= 'F') return static_cast<std::uint8_t>(value - 'A' + 10);
    throw std::invalid_argument("public key contains a non-hex character");
}

std::vector<std::uint8_t> parsePublicKey(std::string_view encoded) {
    std::string normalized;
    normalized.reserve(encoded.size());
    for (const char value : encoded) {
        if (!std::isspace(static_cast<unsigned char>(value))) {
            normalized.push_back(value);
        }
    }

    if (normalized.size() != 130) {
        throw std::invalid_argument("public key must contain exactly 130 hex digits");
    }
    std::vector<std::uint8_t> result;
    result.reserve(normalized.size() / 2);
    for (std::size_t index = 0; index < normalized.size(); index += 2) {
        result.push_back(static_cast<std::uint8_t>(
            (hexDigit(normalized[index]) << 4) | hexDigit(normalized[index + 1])
        ));
    }
    return result;
}

std::string readClipboardText() {
    if (OpenClipboard(nullptr) == FALSE) {
        throw std::runtime_error("could not open the Windows clipboard");
    }

    const auto closeClipboard = []() { CloseClipboard(); };
    const HANDLE handle = GetClipboardData(CF_UNICODETEXT);
    if (handle == nullptr) {
        closeClipboard();
        throw std::runtime_error("the Windows clipboard does not contain Unicode text");
    }

    const auto text = static_cast<const wchar_t*>(GlobalLock(handle));
    if (text == nullptr) {
        closeClipboard();
        throw std::runtime_error("could not read Unicode text from the Windows clipboard");
    }

    std::string result;
    for (const wchar_t value : std::wstring_view(text)) {
        if (value > 0x7f) {
            GlobalUnlock(handle);
            closeClipboard();
            throw std::invalid_argument("clipboard text contains non-ASCII characters");
        }
        result.push_back(static_cast<char>(value));
    }

    GlobalUnlock(handle);
    closeClipboard();
    return result;
}

bool confirm(std::string_view word) {
    std::cout << "Type " << word << " to continue: ";
    std::string input;
    std::getline(std::cin, input);
    return input == word;
}

std::wstring modulePath() {
    std::wstring path(32'768, L'\0');
    const DWORD length = GetModuleFileNameW(nullptr, path.data(), static_cast<DWORD>(path.size()));
    if (length == 0 || length >= path.size()) {
        throw std::runtime_error("GetModuleFileNameW failed");
    }
    path.resize(length);
    return path;
}

std::wstring startMenuShortcutPath() {
    std::wstring appData(32'768, L'\0');
    const DWORD length = GetEnvironmentVariableW(
        L"APPDATA",
        appData.data(),
        static_cast<DWORD>(appData.size())
    );
    if (length == 0 || length >= appData.size()) {
        throw std::runtime_error("APPDATA is not available");
    }
    appData.resize(length);
    return appData + L"\\Microsoft\\Windows\\Start Menu\\Programs\\Unlock Windows with iPhone.lnk";
}

void ensureToastShortcut() {
    const auto path = startMenuShortcutPath();
    if (GetFileAttributesW(path.c_str()) != INVALID_FILE_ATTRIBUTES) {
        return;
    }

    const auto separator = path.find_last_of(L'\\');
    const auto directory = path.substr(0, separator);
    std::error_code directoryError;
    std::filesystem::create_directories(directory, directoryError);
    if (directoryError) {
        throw std::runtime_error("could not create the Start menu shortcut directory");
    }

    com_ptr<IShellLinkW> shellLink;
    check_hresult(CoCreateInstance(
        CLSID_ShellLink,
        nullptr,
        CLSCTX_INPROC_SERVER,
        IID_PPV_ARGS(shellLink.put())
    ));
    check_hresult(shellLink->SetPath(modulePath().c_str()));
    check_hresult(shellLink->SetArguments(L""));

    com_ptr<IPropertyStore> propertyStore;
    check_hresult(shellLink->QueryInterface(IID_PPV_ARGS(propertyStore.put())));
    PROPVARIANT appId{};
    check_hresult(InitPropVariantFromString(kAppUserModelId, &appId));
    const auto propertyResult = propertyStore->SetValue(PKEY_AppUserModel_ID, appId);
    PropVariantClear(&appId);
    check_hresult(propertyResult);
    check_hresult(propertyStore->Commit());

    com_ptr<IPersistFile> persistFile;
    check_hresult(shellLink->QueryInterface(IID_PPV_ARGS(persistFile.put())));
    check_hresult(persistFile->Save(path.c_str(), TRUE));
}

bool showEnrollmentToast(const std::string& fingerprint) {
    ensureToastShortcut();

    std::wstring wideFingerprint(fingerprint.begin(), fingerprint.end());
    const std::wstring xmlText =
        L"<toast launch=\"enrollment\">"
        L"<visual><binding template=\"ToastGeneric\">"
        L"<text>Unlock Windows with iPhone</text>"
        L"<text>Confirm enrollment fingerprint: " + wideFingerprint +
        L"</text></binding></visual>"
        L"<actions>"
        L"<action content=\"Confirm enrollment\" arguments=\"confirm\" activationType=\"foreground\"/>"
        L"<action content=\"Cancel\" arguments=\"cancel\" activationType=\"foreground\"/>"
        L"</actions></toast>";

    XmlDocument document;
    document.LoadXml(xmlText);
    ToastNotification toast(document);

    std::mutex mutex;
    std::condition_variable condition;
    enum class PromptResult {
        pending,
        accepted,
        cancelled,
        fallback,
    };
    PromptResult promptResult = PromptResult::pending;
    const auto finish = [&](const PromptResult value) {
        std::lock_guard lock(mutex);
        if (promptResult != PromptResult::pending) {
            return;
        }
        promptResult = value;
        condition.notify_one();
    };

    toast.Activated([&](auto const&, auto const& sender) {
        const auto arguments = sender.as<ToastActivatedEventArgs>().Arguments();
        finish(arguments == L"confirm"
            ? PromptResult::accepted
            : PromptResult::cancelled);
    });
    toast.Dismissed([&](auto const&, auto const&) { finish(PromptResult::fallback); });
    toast.Failed([&](auto const&, auto const&) { finish(PromptResult::fallback); });

    try {
        ToastNotificationManager::CreateToastNotifier(kAppUserModelId).Show(toast);
    } catch (...) {
        std::cerr << "[PairingTool] Windows toast submission failed; using visible confirmation dialog.\n";
        finish(PromptResult::fallback);
    }
    std::unique_lock lock(mutex);
    condition.wait_for(lock, std::chrono::seconds(15), [&]() {
        return promptResult != PromptResult::pending;
    });
    if (promptResult == PromptResult::accepted) {
        return true;
    }
    if (promptResult == PromptResult::cancelled) {
        return false;
    }

    lock.unlock();

    const std::wstring message =
        L"Windows with iPhone enrollment request\n\n"
        L"Fingerprint:\n" + wideFingerprint +
        L"\n\nThe Windows notification was not available or was not acknowledged.\n"
        L"Choose Yes to enroll this iPhone or No to cancel.";
    const int result = MessageBoxW(
        nullptr,
        message.c_str(),
        L"Unlock Windows with iPhone",
        MB_ICONQUESTION | MB_TOPMOST | MB_SETFOREGROUND | MB_YESNO
    );
    return result == IDYES;
}

void reloadSavedCredentialEnrollment() {
    unlock_windows::saved_credential::Packet response;
    if (!unlock_windows::saved_credential::call(
            unlock_windows::saved_credential::Operation::reloadPhoneEnrollment,
            unlock_windows::saved_credential::SensitiveBytes{}, response) ||
        response.result != unlock_windows::saved_credential::Result::success) {
        throw std::runtime_error("saved-credential service enrollment reload failed; run elevated on the unlocked console");
    }
}

} // namespace

int main(int argc, char* argv[]) {
    try {
        if (argc < 2) {
            printUsage();
            return 2;
        }

        unlock_windows::service::EnrollmentStore store;
        if (std::string_view(argv[1]) == "--clear") {
            if (!confirm("REMOVE")) {
                std::cout << "Enrollment was not changed.\n";
                return 1;
            }
            reloadSavedCredentialEnrollment();
            store.remove();
            reloadSavedCredentialEnrollment();
            std::cout << "Enrollment removed from the protected local store.\n";
            return 0;
        }

        const std::string_view command = argv[1];
        const bool clipboard = command == "--key-clipboard";
        const bool hex = command == "--key-hex";
        if (!clipboard && !hex) {
            printUsage();
            return 2;
        }

        const int expectedArguments = clipboard ? 2 : 3;
        if (argc < expectedArguments || argc > expectedArguments + 1) {
            printUsage();
            return 2;
        }
        const bool replace = (clipboard && argc == 3 && std::string_view(argv[2]) == "--replace") ||
            (hex && argc == 4 && std::string_view(argv[3]) == "--replace");
        if ((clipboard && argc == 3 && !replace) || (hex && argc == 4 && !replace)) {
            printUsage();
            return 2;
        }

        const auto publicKey = clipboard
            ? parsePublicKey(readClipboardText())
            : parsePublicKey(argv[2]);
        if (store.load() && !replace) {
            throw std::runtime_error("an enrollment key already exists; use --replace explicitly");
        }

        std::cout << "Candidate public-key fingerprint: "
                  << unlock_windows::service::EnrollmentStore::fingerprint(publicKey) << "\n"
                  << "Compare this fingerprint with the one displayed by the iPhone.\n";
        winrt::init_apartment(winrt::apartment_type::single_threaded);
        const bool accepted = showEnrollmentToast(
            unlock_windows::service::EnrollmentStore::fingerprint(publicKey)
        );
        winrt::uninit_apartment();
        if (!accepted) {
            std::cout << "Enrollment was not confirmed.\n";
            return 3;
        }

        reloadSavedCredentialEnrollment();
        store.save({publicKey, unlock_windows::service::EnrollmentStore::currentUserSid()});
        reloadSavedCredentialEnrollment();

        std::cout << "Enrollment saved to the protected local store.\n";
        return 0;
    } catch (const std::exception& error) {
        std::cerr << "[PairingTool] " << error.what() << "\n";
        return 1;
    }
}
