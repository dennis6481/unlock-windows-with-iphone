// Created by Rui MA on 09 Oct 2026

#include "PasswordPage.xaml.h"
#include "PasswordPage.g.cpp"
#include "PageControls.h"
#include "../../DesktopApp.h"
#include "../../../Enrollment/EnrollmentSession.h"
#include <shellapi.h>
#include <utility>
#include <vector>

namespace winrt::UnlockDesktop::implementation {
using namespace unlock_windows::desktop_app::dashboard_ui;
using namespace unlock_windows::saved_credential;
using namespace Microsoft::UI::Xaml;

void PasswordPage::OnNavigatedTo(Microsoft::UI::Xaml::Navigation::NavigationEventArgs const&) {
    if (passwordPanel_) return;
    passwordPanel_ = StackPanel{};
    passwordPanel_.Spacing(kCardSpacing);
    account_ = text(L"Loading...");
    passwordPanel_.Children().Append(settingsCard(L"Windows account", account_, L"\xE77B"));
    notice_ = InfoBar{};
    notice_.Severity(InfoBarSeverity::Error);
    retry_ = Button{};
    retry_.Content(box_value(L"Retry"));
    retry_.Visibility(Visibility::Collapsed);
    retry_.Click([weak = get_weak()](const auto&, const auto&) {
        if (auto page = weak.get()) {
            try { page->Refresh(); }
            catch (const hresult_error& error) { page->uiError(error); }
        }
    });
    notice_.ActionButton(retry_);
    password_ = Button{};
    password_.Content(box_value(L"Save"));
    password_.Click([weak = get_weak()](const auto&, const auto&) {
        if (auto page = weak.get(); page && page->summary_) {
            try { page->beginOperation(page->summary_->credentialPresent ? Operation::updateCredential : Operation::setCredential); }
            catch (const hresult_error& error) { page->uiError(error); }
        }
    });
    remove_ = Button{};
    remove_.Content(box_value(L"Remove"));
    remove_.Click([weak = get_weak()](const auto&, const auto&) {
        if (auto page = weak.get()) {
            try { page->beginOperation(Operation::clearCredential); }
            catch (const hresult_error& error) { page->uiError(error); }
        }
    });
    management_ = Markup::XamlReader::Load(LR"(<Expander
        xmlns="http://schemas.microsoft.com/winfx/2006/xaml/presentation"
        xmlns:x="http://schemas.microsoft.com/winfx/2006/xaml">
        <Expander.Resources>
            <Style x:Key="PasswordExpanderHeaderStyle" TargetType="ToggleButton">
                <Setter Property="UseSystemFocusVisuals" Value="True"/>
                <Setter Property="Foreground" Value="{ThemeResource TextFillColorPrimaryBrush}"/>
                <Setter Property="Template">
                    <Setter.Value>
                        <ControlTemplate TargetType="ToggleButton">
                            <Grid x:Name="HeaderRoot" Background="{TemplateBinding Background}"
                                BorderBrush="{TemplateBinding BorderBrush}" BorderThickness="{TemplateBinding BorderThickness}"
                                CornerRadius="{TemplateBinding CornerRadius}" Padding="16"
                                MinHeight="{TemplateBinding MinHeight}">
                                <Grid.ColumnDefinitions>
                                    <ColumnDefinition Width="*"/><ColumnDefinition Width="Auto"/>
                                </Grid.ColumnDefinitions>
                                <VisualStateManager.VisualStateGroups>
                                    <VisualStateGroup x:Name="CommonStates">
                                        <VisualState x:Name="Normal"/>
                                        <VisualState x:Name="PointerOver">
                                            <VisualState.Setters>
                                                <Setter Target="HeaderRoot.Background" Value="{ThemeResource SubtleFillColorSecondaryBrush}"/>
                                            </VisualState.Setters>
                                        </VisualState>
                                        <VisualState x:Name="Pressed">
                                            <VisualState.Setters>
                                                <Setter Target="HeaderRoot.Background" Value="{ThemeResource SubtleFillColorTertiaryBrush}"/>
                                            </VisualState.Setters>
                                        </VisualState>
                                        <VisualState x:Name="Checked">
                                            <VisualState.Setters>
                                                <Setter Target="Chevron.Glyph" Value="&#xE70E;"/>
                                            </VisualState.Setters>
                                        </VisualState>
                                        <VisualState x:Name="CheckedPointerOver">
                                            <VisualState.Setters>
                                                <Setter Target="HeaderRoot.Background" Value="{ThemeResource SubtleFillColorSecondaryBrush}"/>
                                                <Setter Target="Chevron.Glyph" Value="&#xE70E;"/>
                                            </VisualState.Setters>
                                        </VisualState>
                                        <VisualState x:Name="CheckedPressed">
                                            <VisualState.Setters>
                                                <Setter Target="HeaderRoot.Background" Value="{ThemeResource SubtleFillColorTertiaryBrush}"/>
                                                <Setter Target="Chevron.Glyph" Value="&#xE70E;"/>
                                            </VisualState.Setters>
                                        </VisualState>
                                        <VisualState x:Name="Disabled">
                                            <VisualState.Setters>
                                                <Setter Target="HeaderContent.Foreground" Value="{ThemeResource TextFillColorDisabledBrush}"/>
                                                <Setter Target="Chevron.Foreground" Value="{ThemeResource TextFillColorDisabledBrush}"/>
                                            </VisualState.Setters>
                                        </VisualState>
                                    </VisualStateGroup>
                                </VisualStateManager.VisualStateGroups>
                                <ContentPresenter x:Name="HeaderContent" Content="{TemplateBinding Content}"
                                    ContentTemplate="{TemplateBinding ContentTemplate}"
                                    ContentTemplateSelector="{TemplateBinding ContentTemplateSelector}"
                                    Foreground="{TemplateBinding Foreground}" VerticalAlignment="Center"/>
                                <FontIcon x:Name="Chevron" Grid.Column="1" Glyph="&#xE70D;"
                                    FontFamily="Segoe Fluent Icons, Segoe MDL2 Assets" FontSize="12"
                                    Margin="16,0,0,0" VerticalAlignment="Center" IsHitTestVisible="False"
                                    AutomationProperties.AccessibilityView="Raw"/>
                            </Grid>
                        </ControlTemplate>
                    </Setter.Value>
                </Setter>
            </Style>
        </Expander.Resources>
    </Expander>)").as<Expander>();
    management_.MinHeight(kCardMinHeight);
    management_.HorizontalAlignment(HorizontalAlignment::Stretch);
    management_.HorizontalContentAlignment(HorizontalAlignment::Stretch);
    management_.Loaded([weak = get_weak()](const auto&, const auto&) {
        if (auto page = weak.get()) {
            try {
                page->management_.ApplyTemplate();
                std::vector<DependencyObject> elements{page->management_};
                while (!elements.empty()) {
                    auto element = elements.back();
                    elements.pop_back();
                    if (auto toggle = element.try_as<Primitives::ToggleButton>();
                        toggle && toggle.Name() == L"ExpanderHeader") {
                        toggle.Style(page->management_.Resources().Lookup(
                            box_value(L"PasswordExpanderHeaderStyle")).as<Microsoft::UI::Xaml::Style>());
                        return;
                    }
                    const auto count = Media::VisualTreeHelper::GetChildrenCount(element);
                    for (int index = 0; index < count; ++index)
                        elements.push_back(Media::VisualTreeHelper::GetChild(element, index));
                }
                throw hresult_error(E_UNEXPECTED, L"The password Expander header was not found.");
            } catch (const hresult_error& failure) { page->uiError(failure); }
        }
    });
    auto header = Markup::XamlReader::Load(LR"(<Grid
        xmlns="http://schemas.microsoft.com/winfx/2006/xaml/presentation">
        <Grid.ColumnDefinitions>
            <ColumnDefinition Width="Auto"/><ColumnDefinition Width="*"/>
        </Grid.ColumnDefinitions>
        <FontIcon FontFamily="Segoe Fluent Icons, Segoe MDL2 Assets" Glyph="&#xE72E;"
            FontSize="20" Margin="0,0,20,0" VerticalAlignment="Center"/>
        <TextBlock Grid.Column="1" Text="Manage saved password" TextWrapping="Wrap"
            VerticalAlignment="Center"/>
    </Grid>)").as<Grid>();
    management_.Header(header);
    StackPanel actions;
    actions.Spacing(16);
    actions.Margin({40, 0, 0, 0});
    const auto actionRow = [](const TextBlock& label, const Button& button) {
        Grid row;
        ColumnDefinition labelColumn, buttonColumn;
        labelColumn.Width(star()); buttonColumn.Width(automatic());
        row.ColumnDefinitions().Append(labelColumn);
        row.ColumnDefinitions().Append(buttonColumn);
        label.VerticalAlignment(VerticalAlignment::Center);
        label.Margin({0, 0, 16, 0});
        button.VerticalAlignment(VerticalAlignment::Center);
        button.MinWidth(100);
        Grid::SetColumn(button, 1);
        row.Children().Append(label);
        row.Children().Append(button);
        return row;
    };
    passwordLabel_ = text(L"Save password");
    actions.Children().Append(actionRow(passwordLabel_, password_));
    removeRow_ = actionRow(text(L"Remove saved password"), remove_);
    actions.Children().Append(removeRow_);
    management_.Content(actions);
    passwordPanel_.Children().Append(management_);
    passwordPanel_.Children().Append(notice_);
    BodyHost().Content(passwordPanel_);
    applyState();
}

void PasswordPage::Bind(unlock_windows::desktop_app::Dashboard::ReportError reportError) {
    reportError_ = std::move(reportError);
}

void PasswordPage::applyState() {
    const bool ready = summary_.has_value() && !loading_ && !managing_ && !stopped_;
    password_.IsEnabled(ready);
    password_.Content(box_value(hstring(summary_ && summary_->credentialPresent ? L"Update" : L"Save")));
    passwordLabel_.Text(summary_ && summary_->credentialPresent ? L"Update saved password" : L"Save password");
    removeRow_.Visibility(summary_ && summary_->credentialPresent ? Visibility::Visible : Visibility::Collapsed);
    remove_.IsEnabled(ready && summary_->credentialPresent);
    if (!summary_) {
        account_.Text(loading_ ? L"Loading..." : L"Not yet verified");
        return;
    }
    const auto& name = summary_->identity.qualifiedUserName;
    const auto separator = name.find_last_of(L'\\');
    account_.Text(name.substr(separator == std::wstring::npos ? 0 : separator + 1));
    if (!summary_->credentialPresent) management_.IsExpanded(true);
    else if (!summary_->credentialMatches) {
        notice_.Severity(InfoBarSeverity::Warning);
        notice_.Message(L"The saved copy does not match this verified Windows identity. Update it before using iPhone unlock.");
        notice_.IsOpen(true);
    }
}

void PasswordPage::error(const std::wstring& message) {
    notice_.Severity(InfoBarSeverity::Error);
    notice_.Message(message);
    notice_.IsOpen(true);
    reportError_(L"Password: " + message);
}

void PasswordPage::Refresh() {
    if (stopped_ || loading_ || managing_) return;
    loading_ = true;
    summary_.reset();
    notice_.IsOpen(false);
    retry_.Visibility(Visibility::Collapsed);
    applyState();
    query_ = query(get_weak(), DispatcherQueue(), reportError_);
}

void PasswordPage::uiError(const hresult_error& failure) {
    rethrowNonlocalUiError(failure);
    Stop();
    retry_.Visibility(Visibility::Collapsed);
    password_.IsEnabled(false);
    remove_.IsEnabled(false);
    error(L"Password UI: " + std::wstring(failure.message()));
}

void PasswordPage::beginOperation(Operation operation) {
    if (stopped_ || loading_ || managing_ || !summary_ ||
        (operation == Operation::clearCredential && !summary_->credentialPresent)) return;
    managing_ = true;
    notice_.IsOpen(false);
    retry_.Visibility(Visibility::Collapsed);
    applyState();
    operation_ = launch(get_weak(), DispatcherQueue(), operation, reportError_);
}

void PasswordPage::Stop() {
    stopped_ = true;
    if (query_) query_.Cancel();
    if (operation_) operation_.Cancel();
}

Windows::Foundation::IAsyncAction PasswordPage::query(weak_ref<PasswordPage> weak,
    Microsoft::UI::Dispatching::DispatcherQueue dispatcher,
    unlock_windows::desktop_app::Dashboard::ReportError reportError) {
    const auto cancellation = co_await get_cancellation_token();
    co_await resume_background();
    if (cancellation()) co_return;
    std::optional<CredentialSummary> summary;
    std::wstring failure;
    try {
        Packet response;
        CallDiagnostics diagnostics;
        if (!call(Operation::credentialSummary, SensitiveBytes{}, response, kPipeTransferLifetimeMs, &diagnostics))
            failure = L"Saved password service is unavailable: " + std::wstring(callStageName(diagnostics.stage)) +
                L" (Win32 " + std::to_wstring(diagnostics.win32Error) + L"). Choose Retry to check again.";
        else if (response.result != Result::success)
            failure = L"The service could not verify this signed-in Windows account. Choose Retry to check again.";
        else {
            CredentialSummary value;
            if (!decodeCredentialSummary(response.payload.value.data(), response.payload.value.size(), value))
                failure = L"The service returned malformed password status.";
            else summary = std::move(value);
            if (diagnostics.stage == CallStage::replyAcknowledgment)
                reportError(L"Password status reply acknowledgment failed (Win32 " + std::to_wstring(diagnostics.win32Error) + L").");
        }
    } catch (...) { failure = currentException(); }
    if (cancellation()) co_return;
    if (!dispatcher.TryEnqueue([weak, summary = std::move(summary), failure = std::move(failure)]() mutable {
        if (auto page = weak.get(); page && !page->stopped_) {
            try {
                page->loading_ = false;
                page->summary_ = std::move(summary);
                page->applyState();
                if (!failure.empty()) {
                    page->error(failure);
                    page->retry_.Visibility(Visibility::Visible);
                }
            } catch (const hresult_error& error) {
                page->uiError(error);
            }
        }
    })) reportError(L"The Password UI dispatcher rejected a status update.");
}

Windows::Foundation::IAsyncAction PasswordPage::launch(weak_ref<PasswordPage> weak,
    Microsoft::UI::Dispatching::DispatcherQueue dispatcher, Operation operation,
    unlock_windows::desktop_app::Dashboard::ReportError reportError) {
    const auto cancellation = co_await get_cancellation_token();
    co_await resume_background();
    if (cancellation()) co_return;
    std::wstring failure;
    unlock_windows::enrollment::Handle process;
    try {
        init_apartment(apartment_type::multi_threaded);
        struct Apartment final { ~Apartment() { uninit_apartment(); } } apartment;
        std::wstring executable(32768, L'\0');
        const auto size = GetModuleFileNameW(nullptr, executable.data(), static_cast<DWORD>(executable.size()));
        if (!size || size >= executable.size()) throw std::runtime_error("Could not locate the password window");
        executable.resize(size);
        const auto arguments = std::wstring(unlock_windows::desktop_app::kSavedPasswordRole) + L" " +
            unlock_windows::desktop_app::passwordOperationArgument(operation);
        SHELLEXECUTEINFOW request{sizeof(request)};
        request.fMask = SEE_MASK_NOCLOSEPROCESS | SEE_MASK_NOASYNC | SEE_MASK_FLAG_NO_UI;
        request.lpVerb = L"runas";
        request.lpFile = executable.c_str();
        request.lpParameters = arguments.c_str();
        request.nShow = SW_SHOWNORMAL;
        if (!ShellExecuteExW(&request)) {
            const auto code = GetLastError();
            if (code != ERROR_CANCELLED) throw std::runtime_error("Open password window: Win32=" + std::to_string(code));
        } else {
            process.value = request.hProcess;
            if (!process.value) throw std::runtime_error("Password window returned no process handle");
        }
    } catch (...) { failure = currentException(); }
    if (process.value) {
        try {
            co_await resume_on_signal(process.value);
            DWORD result = 0;
            unlock_windows::enrollment::require(GetExitCodeProcess(process.value, &result), "Read password window result");
            if (result == static_cast<DWORD>(unlock_windows::desktop_app::SetupResult::error))
                failure = L"The password window did not complete successfully. Try the password action again.";
        } catch (...) { failure = currentException(); }
    }
    if (cancellation()) co_return;
    if (!dispatcher.TryEnqueue([weak, failure = std::move(failure)] {
        if (auto page = weak.get(); page && !page->stopped_) {
            try {
                page->managing_ = false;
                page->Refresh();
                if (!failure.empty()) page->error(failure);
            } catch (const hresult_error& error) {
                page->uiError(error);
            }
        }
    })) reportError(L"The Password UI dispatcher rejected a password operation result.");
}
}
