// Created by Rui MA on 09 Oct 2026

#include "DesktopApp.h"
#include "DesktopApplication.h"
#include "TrayManager.h"
#include "Dashboard/Dashboard.h"
#include "Dashboard/Pages/PageControls.h"
#include "../GattHost/GattController.h"
#include "../Resources/DesktopUi.h"
#include <WtsApi32.h>
#include <winrt/Microsoft.UI.Dispatching.h>
#include <winrt/Microsoft.UI.Xaml.h>
#include <memory>
#include <chrono>

namespace unlock_windows::desktop_app {
namespace {
using namespace winrt;
using namespace Microsoft::UI;
using namespace Microsoft::UI::Xaml;

constexpr ULONGLONG kShutdownReportDelayMs = 10000;

class DesktopHost final : public std::enable_shared_from_this<DesktopHost> {
public:
    DesktopHost(HINSTANCE instance, bool setup, bool background) : instance_(instance), setup_(setup), background_(background),
        tray_([this](TrayCommand command) {
                switch (command) {
                case TrayCommand::showWindow: show(); break;
                case TrayCommand::status: show(DashboardPage::status); break;
                case TrayCommand::password: show(DashboardPage::password); break;
                case TrayCommand::about: show(DashboardPage::about); break;
                default: execute(command); break;
                }
            },
            [this](const std::wstring& message, bool error) { controller_->record((error ? L"Tray error: " : L"Tray: ") + message); }) {
        snapshot_.busy = true;
        snapshot_.status = L"Starting Bluetooth discovery...";
    }
    ~DesktopHost() { if (singleton_) CloseHandle(singleton_); }

    bool prepare() {
        desktop_ui::require(ProcessIdToSessionId(GetCurrentProcessId(), &session_), "ProcessIdToSessionId");
        singleton_ = CreateMutexW(nullptr, FALSE, L"Local\\UnlockWindowsWithIPhone-GattHost");
        desktop_ui::require(singleton_ != nullptr, "CreateMutexW");
        if (GetLastError() != ERROR_ALREADY_EXISTS) return true;
        if (setup_ || !background_) {
            HWND existing = nullptr;
            for (int attempt = 0; attempt < 40 && !existing; ++attempt) {
                existing = FindWindowW(kTrayWindowClass, nullptr);
                if (!existing) Sleep(50);
            }
            if (!existing) throw std::runtime_error("The existing tray is not ready. Wait for startup to finish and retry.");
            DWORD pid = 0, session = 0xffffffff;
            GetWindowThreadProcessId(existing, &pid);
            desktop_ui::require(pid && ProcessIdToSessionId(pid, &session) && session == session_, "Verify setup tray session");
            desktop_ui::require(PostMessageW(existing, setup_ ? kSetupMessage : kShowDashboardMessage, 0, 0),
                "Request setup or activation from tray");
        }
        return false;
    }

    void launch() {
        dispatcher_ = Dispatching::DispatcherQueue::GetForCurrentThread();
        if (!dispatcher_) throw std::runtime_error("The WinUI dispatcher is unavailable");
        const auto weak = weak_from_this();
        controller_ = std::make_unique<GattController>([weak, dispatcher = dispatcher_] {
            return dispatcher.TryEnqueue([weak] {
                if (const auto host = weak.lock()) host->poll();
            });
        });
        dashboard_ = std::make_unique<Dashboard>(
            [weak](bool remove) { if (const auto host = weak.lock()) host->execute(remove ? TrayCommand::removePhone : TrayCommand::pairPhone); },
            [weak] { if (const auto host = weak.lock()) host->execute(TrayCommand::status); },
            controller_->errorReporter(L"Dashboard needs attention"), controller_->errorReporter(L"", false));
        timer_ = dispatcher_.CreateTimer();
        timer_.Interval(std::chrono::seconds(1));
        timerToken_ = timer_.Tick([weak](const auto&, const auto&) {
            if (const auto host = weak.lock()) host->poll();
        });
        timer_.Start();
        shutdownToken_ = dispatcher_.ShutdownStarting([weak](const auto&, const auto& args) {
            if (const auto host = weak.lock(); host && !host->completed_) {
                host->shutdownDeferral_ = args.GetDeferral();
                host->requestStop();
                host->poll();
            }
        });
        if (!dispatcher_.TryEnqueue([weak] {
            if (const auto host = weak.lock()) {
                if (host->stopping_) { host->poll(); return; }
                host->controller_->start(host->instance_);
            }
        })) {
            report(L"The WinUI dispatcher rejected the GATT startup task.", L"Desktop startup failed");
            exitCode_ = 1;
            requestStop();
            poll();
        }
    }

    int result() const { return exitCode_; }
    bool completed() const { return completed_; }

    void finishAfterLoop() {
        stopping_ = true;
        if (controller_) {
            controller_->requestStop();
            if (!controller_->ended()) RaiseFailFastException(nullptr, nullptr, 0);
        }
        finish();
    }

private:
    void report(const std::wstring& message, const wchar_t* title) {
        if (controller_) controller_->record(L"Desktop: " + message);
        MessageBoxW(window_, message.c_str(), title, MB_OK | MB_ICONERROR);
    }

    void bindTray() {
        tray_.loadIcon(instance_);
        WNDCLASSW windowClass{};
        windowClass.hInstance = instance_;
        windowClass.hIcon = tray_.icon();
        windowClass.lpszClassName = kTrayWindowClass;
        windowClass.lpfnWndProc = windowProcedure;
        desktop_ui::require(RegisterClassW(&windowClass), "RegisterClassW(tray)");
        window_ = CreateWindowExW(0, kTrayWindowClass, UNLOCK_PRODUCT_DISPLAY_NAME,
            0, 0, 0, 0, 0, nullptr, nullptr, instance_, this);
        desktop_ui::require(window_ != nullptr, "CreateWindowExW(tray)");
        tray_.bind(window_, snapshot_.status);
        if (setup_) execute(TrayCommand::continueSetup);
        else if (!background_) show();
    }

    void show(std::optional<DashboardPage> page = std::nullopt) {
        if (stopping_) { report(L"The desktop app is stopping; the request was cancelled.", L"Operation cancelled"); return; }
        dashboard_->update(snapshot_);
        dashboard_->show(page);
        execute(TrayCommand::status);
    }

    void execute(TrayCommand command) {
        if (command == TrayCommand::quit) { requestStop(); return; }
        if (stopping_ || !controller_->command(command))
            report(L"The desktop app is stopping; the request was cancelled.", L"Operation cancelled");
    }

    void requestStop() {
        if (stopping_) return;
        stopping_ = true;
        stopRequestedAt_ = GetTickCount64();
        controller_->requestStop();
        dashboard_->stop();
    }

    void poll() {
        if (completed_ || polling_) return;
        polling_ = true;
        struct Poll final { bool& active; ~Poll() { active = false; } } poll{polling_};
        auto update = controller_->takeUpdate();
        if (update.failed) exitCode_ = 1;
        if (update.stopping) requestStop();
        if (update.snapshot && !stopping_) {
            snapshot_ = std::move(*update.snapshot);
            dashboard_->update(snapshot_);
        }
        try {
            if (update.controlReady && !window_ && !stopping_) bindTray();
            if (window_ && !stopping_) {
                tray_.update(snapshot_.error.empty() ? snapshot_.status : L"Needs attention: " + snapshot_.status);
                tray_.retryRegistration();
            }
        } catch (const std::runtime_error& error) {
            exitCode_ = 1;
            requestStop();
            report(std::wstring(to_hstring(error.what())), L"Desktop window failed");
        }
        if (stopping_ && controller_->ended()) {
            finish();
            for (const auto& notice : update.notices) {
                if (!(notice.flags & MB_ICONERROR)) continue;
                MessageBoxW(nullptr, notice.message.c_str(), notice.title.c_str(), notice.flags);
                break;
            }
            Application::Current().Exit();
            return;
        } else if (stopping_ && !stopTimeoutReported_ && GetTickCount64() - stopRequestedAt_ >= kShutdownReportDelayMs) {
            stopTimeoutReported_ = true;
            polling_ = false;
            report(L"Exit has not completed: the Bluetooth control thread is still stopping. The app remains responsive and will exit when cleanup finishes.",
                L"Exit needs attention");
        }
        polling_ = false;
        for (const auto& notice : update.notices) {
            if (completed_) break;
            if (stopping_ && !(notice.flags & MB_ICONERROR)) continue;
            MessageBoxW(window_, notice.message.c_str(), notice.title.c_str(), notice.flags);
        }
    }

    void finish() {
        if (completed_) return;
        if (controller_) controller_->join();
        if (dashboard_) dashboard_->stop();
        tray_.stop();
        if (window_) {
            desktop_ui::require(DestroyWindow(window_), "DestroyWindow(tray)");
            window_ = nullptr;
        }
        tray_.releaseIcon();
        if (timer_) {
            timer_.Stop();
            timer_.Tick(timerToken_);
        }
        if (shutdownToken_.value) dispatcher_.ShutdownStarting(shutdownToken_);
        completed_ = true;
        if (shutdownDeferral_) {
            shutdownDeferral_.Complete();
            shutdownDeferral_ = nullptr;
        }
    }

    static LRESULT CALLBACK windowProcedure(HWND window, UINT message, WPARAM wparam, LPARAM lparam) {
        auto* self = reinterpret_cast<DesktopHost*>(GetWindowLongPtrW(window, GWLP_USERDATA));
        if (message == WM_NCCREATE) {
            self = static_cast<DesktopHost*>(reinterpret_cast<CREATESTRUCTW*>(lparam)->lpCreateParams);
            SetWindowLongPtrW(window, GWLP_USERDATA, reinterpret_cast<LONG_PTR>(self));
        }
        if (!self) return DefWindowProcW(window, message, wparam, lparam);
        try {
            if (const auto result = self->tray_.handleMessage(message, wparam, lparam)) return *result;
            switch (message) {
            case kShowDashboardMessage: self->show(); return 0;
            case kSetupMessage: self->execute(TrayCommand::continueSetup); return 0;
            case WM_CLOSE: self->requestStop(); return 0;
            case WM_DESTROY: self->requestStop(); return 0;
            case WM_NCDESTROY:
                self->window_ = nullptr;
                SetWindowLongPtrW(window, GWLP_USERDATA, 0);
                break;
            case WM_QUERYENDSESSION: return TRUE;
            case WM_ENDSESSION: return 0;
            case WM_POWERBROADCAST: return TRUE;
            case WM_WTSSESSION_CHANGE: return 0;
            }
        } catch (const std::runtime_error& error) {
            self->exitCode_ = 1;
            self->requestStop();
            self->report(std::wstring(to_hstring(error.what())), L"Desktop operation failed");
            return 0;
        } catch (...) {
            RaiseFailFastException(nullptr, nullptr, 0);
        }
        return DefWindowProcW(window, message, wparam, lparam);
    }

    HINSTANCE instance_;
    bool setup_, background_;
    HANDLE singleton_ = nullptr;
    DWORD session_ = 0;
    HWND window_ = nullptr;
    Dispatching::DispatcherQueue dispatcher_{nullptr};
    Dispatching::DispatcherQueueTimer timer_{nullptr};
    event_token timerToken_{};
    event_token shutdownToken_{};
    Windows::Foundation::Deferral shutdownDeferral_{nullptr};
    std::unique_ptr<GattController> controller_;
    std::unique_ptr<Dashboard> dashboard_;
    DashboardSnapshot snapshot_;
    TrayManager tray_;
    bool stopping_ = false;
    bool completed_ = false;
    bool polling_ = false;
    bool stopTimeoutReported_ = false;
    ULONGLONG stopRequestedAt_ = 0;
    int exitCode_ = 0;
};
}

int runTray(HINSTANCE instance, bool setup, bool background) {
    std::shared_ptr<DesktopHost> host;
    try {
        desktop_ui::initialize();
        host = std::make_shared<DesktopHost>(instance, setup, background);
        if (!host->prepare()) return 0;
        init_apartment(apartment_type::single_threaded);
        struct Apartment final { ~Apartment() { uninit_apartment(); } } apartment;
        com_ptr<DesktopApplication> app;
        try {
            Application::Start([&](const auto&) {
                app = make_self<DesktopApplication>([weak = std::weak_ptr(host)] {
                    if (const auto current = weak.lock()) current->launch();
                });
            });
            if (!host->completed()) throw std::runtime_error("The WinUI message loop ended before desktop shutdown completed");
            const int result = host->result();
            app = nullptr;
            host.reset();
            return result;
        } catch (...) {
            const auto error = dashboard_ui::currentException();
            MessageBoxW(nullptr, error.c_str(), L"Could not run desktop app", MB_OK | MB_ICONERROR);
            try { host->finishAfterLoop(); }
            catch (...) { RaiseFailFastException(nullptr, nullptr, 0); }
            app = nullptr;
            host.reset();
            return 1;
        }
    } catch (...) {
        const auto error = dashboard_ui::currentException();
        MessageBoxW(nullptr, error.c_str(), L"Could not run desktop app", MB_OK | MB_ICONERROR);
        return 1;
    }
}
}
