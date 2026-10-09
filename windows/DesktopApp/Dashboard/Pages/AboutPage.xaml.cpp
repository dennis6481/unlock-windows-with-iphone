// Created by Rui MA on 09 Oct 2026

#include "AboutPage.xaml.h"
#include "AboutPage.g.cpp"
#include "PageControls.h"
#include "../../../ProductVersion.h"
#include "../../../Resources/resource.h"
#include <winrt/Windows.Data.Json.h>
#include <winrt/Windows.Web.Http.h>
#include <winrt/Windows.Web.Http.Headers.h>
#include <utility>

namespace winrt::UnlockDesktop::implementation {
using namespace unlock_windows::desktop_app::dashboard_ui;
namespace { constexpr wchar_t kProjectUrl[] = L"https://github.com/dennis6481/unlock-windows-with-iphone"; }

void AboutPage::OnNavigatedTo(Microsoft::UI::Xaml::Navigation::NavigationEventArgs const&) {
    if (aboutPanel_) return;
    aboutPanel_ = StackPanel{};
    aboutPanel_.Spacing(16);
    aboutPanel_.Children().Append(text(UNLOCK_PRODUCT_DISPLAY_NAME, 24));
    const auto version = L"Version " + unlock::components::kProductVersion.text();
    aboutPanel_.Children().Append(text(version.c_str()));
    HyperlinkButton project;
    project.Content(box_value(L"GitHub project"));
    project.NavigateUri(Windows::Foundation::Uri(kProjectUrl));
    aboutPanel_.Children().Append(project);
    HyperlinkButton license;
    license.Content(box_value(L"MIT License"));
    license.NavigateUri(Windows::Foundation::Uri(std::wstring(kProjectUrl) + L"/blob/main/LICENSE.md"));
    aboutPanel_.Children().Append(license);
    checkUpdates_ = Button{};
    checkUpdates_.Content(box_value(L"Check for updates"));
    checkUpdates_.Click([weak = get_weak()](const auto&, const auto&) {
        if (auto page = weak.get()) {
            page->checkUpdates_.IsEnabled(false);
            page->updateStatus_.Text(L"Checking for updates...");
            page->release_.Visibility(Visibility::Collapsed);
            page->updateCheck_ = checkForUpdates(weak, page->DispatcherQueue(), page->reportError_);
        }
    });
    aboutPanel_.Children().Append(checkUpdates_);
    updateStatus_ = text(L"");
    aboutPanel_.Children().Append(updateStatus_);
    release_ = HyperlinkButton{};
    release_.Content(box_value(L"View release"));
    release_.Visibility(Visibility::Collapsed);
    aboutPanel_.Children().Append(release_);

    BodyHost().Content(aboutPanel_);
}

void AboutPage::Bind(unlock_windows::desktop_app::Dashboard::ReportError reportError) {
    reportError_ = std::move(reportError);
}

void AboutPage::Stop() {
    stopped_ = true;
    if (updateCheck_) updateCheck_.Cancel();
}

Windows::Foundation::IAsyncAction AboutPage::checkForUpdates(
    weak_ref<AboutPage> weak, Microsoft::UI::Dispatching::DispatcherQueue dispatcher,
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
            else if (*remote > unlock::components::kProductVersion) {
                message = L"Version " + remote->text() + L" is available.";
                releaseUrl = std::wstring(kProjectUrl) + L"/releases/tag/" + std::wstring(tag);
            } else if (*remote == unlock::components::kProductVersion)
                message = L"You are using the latest release.";
            else message = L"Your version is newer than the latest published release (" + remote->text() + L").";
        }
    } catch (...) {
        if (cancellation()) co_return;
        message = failure + currentException();
    }
    if (cancellation()) co_return;
    try {
        if (!dispatcher.TryEnqueue([weak, message = std::move(message), releaseUrl = std::move(releaseUrl)] {
            const auto page = weak.get();
            if (!page || page->stopped_) return;
            page->updateStatus_.Text(message);
            page->checkUpdates_.IsEnabled(true);
            if (!releaseUrl.empty()) {
                page->release_.NavigateUri(Windows::Foundation::Uri(releaseUrl));
                page->release_.Visibility(Visibility::Visible);
            }
        })) reportError(L"The About UI dispatcher rejected an update.");
    } catch (...) { reportError(currentException()); }
}
}
