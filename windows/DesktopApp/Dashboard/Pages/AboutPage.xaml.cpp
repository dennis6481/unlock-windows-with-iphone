// Created by Rui MA on 09 Oct 2026

#include "AboutPage.xaml.h"
#include "AboutPage.g.cpp"
#include "PageControls.h"
#include "../../../ProductVersion.h"
#include <winrt/Windows.Data.Json.h>
#include <winrt/Microsoft.UI.Xaml.Automation.h>
#include <winrt/Windows.Web.Http.h>
#include <winrt/Windows.Web.Http.Headers.h>
#include <utility>

namespace winrt::UnlockDesktop::implementation {
using namespace unlock_windows::desktop_app::dashboard_ui;
namespace {
constexpr wchar_t kProjectUrl[] = L"https://github.com/dennis6481/unlock-windows-with-iphone";

HyperlinkButton externalLink(const wchar_t* label, const wchar_t* glyph, const std::wstring& url) {
    auto link = Markup::XamlReader::Load(LR"(<HyperlinkButton
        xmlns="http://schemas.microsoft.com/winfx/2006/xaml/presentation"
        Foreground="{ThemeResource TextFillColorPrimaryBrush}"
        HorizontalAlignment="Stretch" HorizontalContentAlignment="Stretch"
        Padding="0" BorderThickness="0"/>)").as<HyperlinkButton>();
    auto launchIcon = icon(L"\xE8A7", 16);
    link.Content(settingsCard(label, launchIcon, glyph, false));
    link.NavigateUri(Windows::Foundation::Uri(url));
    Automation::AutomationProperties::SetName(link, label);
    return link;
}
}

void AboutPage::OnNavigatedTo(Microsoft::UI::Xaml::Navigation::NavigationEventArgs const&) {
    if (aboutPanel_) return;
    aboutPanel_ = StackPanel{};
    aboutPanel_.Spacing(kCardSpacing);
    const auto& productVersion = unlock::components::kProductVersion;
    const auto version = L"Version " + std::to_wstring(productVersion.major) + L"." + std::to_wstring(productVersion.minor) +
        L"." + std::to_wstring(productVersion.patch) + L" (Build " + std::to_wstring(productVersion.build) + L")";
    checkUpdates_ = Button{};
    checkUpdates_.Content(box_value(L"Check for updates"));
    checkUpdates_.Click([weak = get_weak()](const auto&, const auto&) {
        if (auto page = weak.get(); page && !page->stopped_) {
            try {
                page->checkUpdates_.IsEnabled(false);
                page->updateStatus_.Text(L"Checking for updates...");
                page->updateStatus_.Visibility(Visibility::Visible);
                page->release_.Visibility(Visibility::Collapsed);
                page->updateCheck_ = checkForUpdates(weak, page->DispatcherQueue(), page->reportError_);
            } catch (const hresult_error& error) {
                rethrowNonlocalUiError(error);
                page->Stop();
                page->reportError_(currentException());
            }
        }
    });
    auto versionCard = settingsCard(version.c_str(), checkUpdates_, L"\xE946", false);
    StackPanel versionContent;
    versionContent.Spacing(16);
    const auto versionRow = versionCard.Child();
    versionCard.Child(nullptr);
    versionContent.Children().Append(versionRow);
    updateStatus_ = text(L"");
    updateStatus_.Visibility(Visibility::Collapsed);
    versionContent.Children().Append(updateStatus_);
    release_ = HyperlinkButton{};
    release_.Content(box_value(L"View release"));
    release_.Visibility(Visibility::Collapsed);
    versionContent.Children().Append(release_);
    versionCard.Child(versionContent);
    aboutPanel_.Children().Append(versionCard);

    for (const auto& link : {
        externalLink(L"GitHub Page", L"\xE71B", kProjectUrl),
        externalLink(L"MIT License", L"\xE8A5", std::wstring(kProjectUrl) + L"/blob/main/LICENSE.md"),
        externalLink(L"Buy me a coffee", L"\xEB51", L"https://www.buymeacoffee.com/dennis6481")}) {
        aboutPanel_.Children().Append(link);
    }

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
            else if (remote->release() > unlock::components::kProductVersion.release()) {
                message = L"Version " + std::wstring(version) + L" is available.";
                releaseUrl = std::wstring(kProjectUrl) + L"/releases/tag/" + std::wstring(tag);
            } else if (remote->release() == unlock::components::kProductVersion.release())
                message = L"You are using the latest release.";
            else message = L"Your version is newer than the latest published release (" + std::wstring(version) + L").";
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
            try {
                page->updateStatus_.Text(message);
                page->checkUpdates_.IsEnabled(true);
                if (!releaseUrl.empty()) {
                    page->release_.NavigateUri(Windows::Foundation::Uri(releaseUrl));
                    page->release_.Visibility(Visibility::Visible);
                }
            } catch (const hresult_error& error) {
                rethrowNonlocalUiError(error);
                page->Stop();
                page->reportError_(currentException());
            }
        })) reportError(L"The About UI dispatcher rejected an update.");
    } catch (...) { reportError(currentException()); }
}
}
