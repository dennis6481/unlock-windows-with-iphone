// Created by Rui MA on 16 Oct 2026

#include "AboutViewModel.h"
#include "AboutViewModel.g.cpp"
#include "../../DesktopErrors.h"
#include "../../../ProductVersion.h"
#include <winrt/Windows.Foundation.h>
#include <winrt/Windows.Data.Json.h>
#include <winrt/Windows.Web.Http.h>
#include <winrt/Windows.Web.Http.Headers.h>

namespace winrt::UnlockDesktop::implementation {
using namespace unlock_windows::desktop_app::dashboard_ui;
using namespace Microsoft::UI::Xaml;
namespace {
constexpr wchar_t kProjectUrl[] = L"https://github.com/dennis6481/unlock-windows-with-iphone";
}

AboutViewModel::AboutViewModel() {
    const auto weak = get_weak();
    check_ = make_self<unlock_windows::desktop_app::ViewModelCommand>(
        [weak] { if (auto model = weak.get()) model->Check(); },
        [weak] { const auto model = weak.get(); return model && !model->stopped_ && !model->checking_; });
}
hstring AboutViewModel::Version() const {
    const auto& version = unlock::components::kProductVersion;
    return hstring{L"Version " + std::to_wstring(version.major) + L"." + std::to_wstring(version.minor) +
        L"." + std::to_wstring(version.patch) + L" (Build " + std::to_wstring(version.build) + L")"};
}
Windows::Foundation::Uri AboutViewModel::ProjectUri() const { return Windows::Foundation::Uri{kProjectUrl}; }
Windows::Foundation::Uri AboutViewModel::LicenseUri() const { return Windows::Foundation::Uri{std::wstring(kProjectUrl) + L"/blob/main/LICENSE.md"}; }
Visibility AboutViewModel::UpdateVisibility() const { return checked_ ? Visibility::Visible : Visibility::Collapsed; }
Visibility AboutViewModel::ReleaseVisibility() const { return release_ ? Visibility::Visible : Visibility::Collapsed; }
void AboutViewModel::Bind(unlock_windows::desktop_app::Dashboard::ReportError reportError) { reportError_ = std::move(reportError); }
void AboutViewModel::Stop() {
    stopped_ = true;
    if (updateCheck_) updateCheck_.Cancel();
    check_->Invalidate();
}
void AboutViewModel::Check() {
    if (stopped_ || checking_) return;
    try {
        checking_ = checked_ = true;
        message_ = L"Checking for updates...";
        release_ = nullptr;
        Notify({L"UpdateStatus", L"UpdateVisibility", L"ReleaseUri", L"ReleaseVisibility"});
        check_->Invalidate();
        updateCheck_ = checkForUpdates(get_weak(), Microsoft::UI::Dispatching::DispatcherQueue::GetForCurrentThread(), reportError_);
    } catch (const hresult_error& error) {
        if (isNonlocalUiError(error)) throw;
        Stop();
        reportError_(formatException(std::current_exception()));
    }
}
Windows::Foundation::IAsyncAction AboutViewModel::checkForUpdates(
    weak_ref<AboutViewModel> weak, Microsoft::UI::Dispatching::DispatcherQueue dispatcher,
    unlock_windows::desktop_app::Dashboard::ReportError reportError) {
    const auto cancellation = co_await get_cancellation_token();
    cancellation.enable_propagation();
    co_await resume_background();
    std::wstring message, releaseUrl;
    std::wstring failure = L"Network update check failed: ";
    try {
        using namespace Windows::Web::Http;
        HttpClient client;
        client.DefaultRequestHeaders().UserAgent().ParseAdd(
            L"UnlockWithIPhone/" + unlock::components::kProductVersion.text());
        client.DefaultRequestHeaders().Accept().ParseAdd(L"application/vnd.github+json");
        const auto repository = std::wstring(kProjectUrl).substr(std::wstring_view(L"https://github.com/").size());
        const auto response = co_await client.GetAsync(Windows::Foundation::Uri(
            L"https://api.github.com/repos/" + repository + L"/releases/latest"));
        const auto status = static_cast<unsigned>(response.StatusCode());
        if (status == 404) message = L"No published release was found, or the repository is unavailable.";
        else if (status == 403 || status == 429)
            message = L"GitHub refused the request or its API limit was reached (HTTP " + std::to_wstring(status) + L"). Try again later.";
        else if (status != 200)
            message = L"Update check failed (HTTP " + std::to_wstring(status) + L").";
        else {
            const auto content = co_await response.Content().ReadAsStringAsync();
            failure = L"GitHub returned an invalid release response: ";
            const auto object = Windows::Data::Json::JsonObject::Parse(content);
            const auto tag = object.GetNamedString(L"tag_name");
            std::wstring_view version(tag.c_str(), tag.size());
            if (!version.empty() && version.front() == L'v') version.remove_prefix(1);
            const auto remote = unlock::components::parseProductVersion(version);
            if (!remote || object.GetNamedBoolean(L"draft") || object.GetNamedBoolean(L"prerelease"))
                message = L"GitHub returned an invalid release version or release type.";
            else if (remote->release() > unlock::components::kProductVersion.release()) {
                message = L"Version " + std::wstring(version) + L" is available.";
                releaseUrl = std::wstring(kProjectUrl) + L"/releases/tag/" + std::wstring(tag);
            } else if (remote->release() == unlock::components::kProductVersion.release())
                message = L"You are using the latest release.";
            else message = L"Your version is newer than the latest published release (" + std::wstring(version) + L").";
        }
    } catch (...) {
        if (cancellation()) co_return;
        message = failure + formatException(std::current_exception());
    }
    if (cancellation()) co_return;
    try {
        if (!dispatcher.TryEnqueue([weak, message = std::move(message), releaseUrl = std::move(releaseUrl)] {
            const auto page = weak.get();
            if (!page || page->stopped_) return;
            try {
                page->message_ = message;
                page->checking_ = false;
                if (!releaseUrl.empty()) {
                    page->release_ = Windows::Foundation::Uri(releaseUrl);
                }
                page->Notify({L"UpdateStatus", L"ReleaseUri", L"ReleaseVisibility"});
                page->check_->Invalidate();
            } catch (const hresult_error& error) {
                if (isNonlocalUiError(error)) throw;
                page->Stop();
                page->reportError_(formatException(std::current_exception()));
            }
        })) reportError(L"The About UI dispatcher rejected an update.");
    } catch (...) { reportError(formatException(std::current_exception())); }
}
}
