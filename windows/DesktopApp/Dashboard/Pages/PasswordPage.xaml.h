// Created by Rui MA on 09 Oct 2026

#pragma once

#include "PasswordPage.g.h"
#include "../Dashboard.h"
#include "../../../SavedCredential/SavedCredentialIpc.h"
#include <winrt/Microsoft.UI.Dispatching.h>
#include <winrt/Microsoft.UI.Xaml.Controls.h>
#include <winrt/Microsoft.UI.Xaml.Navigation.h>

namespace winrt::UnlockDesktop::implementation {
struct PasswordPage : PasswordPageT<PasswordPage> {
    PasswordPage() = default;
    void OnNavigatedTo(Microsoft::UI::Xaml::Navigation::NavigationEventArgs const& args);
    void Bind(unlock_windows::desktop_app::Dashboard::ReportError reportError);
    void Refresh();
    void Stop();

private:
    void applyState();
    void beginOperation(unlock_windows::saved_credential::Operation operation);
    void error(const std::wstring& message);
    void uiError(const hresult_error& error);
    static winrt::Windows::Foundation::IAsyncAction query(weak_ref<PasswordPage> weak,
        Microsoft::UI::Dispatching::DispatcherQueue dispatcher,
        unlock_windows::desktop_app::Dashboard::ReportError reportError);
    static winrt::Windows::Foundation::IAsyncAction launch(weak_ref<PasswordPage> weak,
        Microsoft::UI::Dispatching::DispatcherQueue dispatcher,
        unlock_windows::saved_credential::Operation operation,
        unlock_windows::desktop_app::Dashboard::ReportError reportError);
    Microsoft::UI::Xaml::Controls::StackPanel passwordPanel_{nullptr};
    Microsoft::UI::Xaml::Controls::TextBlock account_{nullptr}, status_{nullptr};
    Microsoft::UI::Xaml::Controls::Button password_{nullptr};
    Microsoft::UI::Xaml::Controls::Button remove_{nullptr};
    Microsoft::UI::Xaml::Controls::InfoBar notice_{nullptr};
    std::optional<unlock_windows::saved_credential::CredentialSummary> summary_;
    unlock_windows::desktop_app::Dashboard::ReportError reportError_;
    winrt::Windows::Foundation::IAsyncAction query_{nullptr}, operation_{nullptr};
    bool loading_ = false, managing_ = false, stopped_ = false;
};
}

namespace winrt::UnlockDesktop::factory_implementation {
struct PasswordPage : PasswordPageT<PasswordPage, implementation::PasswordPage> {};
}
