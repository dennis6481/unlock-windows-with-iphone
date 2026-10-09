// Created by Rui MA on 09 Oct 2026

#include "PasswordPage.xaml.h"
#include "PasswordPage.g.cpp"
#include "PageControls.h"
#include <utility>

namespace winrt::UnlockDesktop::implementation {
using namespace unlock_windows::desktop_app::dashboard_ui;

void PasswordPage::OnNavigatedTo(Microsoft::UI::Xaml::Navigation::NavigationEventArgs const&) {
    if (passwordPanel_) return;
    passwordPanel_ = StackPanel{};
    passwordPanel_.Spacing(16);
    passwordPanel_.Children().Append(text(L"Manage the encrypted copy of your Microsoft account password saved on this PC. This does not change your account password."));
    passwordPanel_.Children().Append(text(L"The password manager verifies your Windows account and lets you save, update or remove the saved copy. Administrator approval is required."));
    password_ = Button{};
    password_.Content(box_value(L"Manage saved password"));
    password_.Click([weak = get_weak()](const auto&, const auto&) { if (auto page = weak.get()) page->managePassword_(); });
    passwordPanel_.Children().Append(password_);

    BodyHost().Content(passwordPanel_);
}

void PasswordPage::Bind(unlock_windows::desktop_app::Dashboard::PasswordAction action) {
    managePassword_ = std::move(action);
}
}
