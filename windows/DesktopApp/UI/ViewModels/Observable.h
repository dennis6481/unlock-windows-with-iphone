// Created by Rui MA on 16 Oct 2026

#pragma once

#include <winrt/Windows.Foundation.h>
#include <winrt/Microsoft.UI.Xaml.Data.h>
#include <winrt/Microsoft.UI.Xaml.Input.h>
#include <functional>
#include <initializer_list>

namespace unlock_windows::desktop_app {
/// Supply the property-change event shared by the four presentation models.
template<typename Derived> struct Observable {
    /// Subscribe to presentation property changes.
    winrt::event_token PropertyChanged(const winrt::Microsoft::UI::Xaml::Data::PropertyChangedEventHandler& handler) {
        return changed_.add(handler);
    }
    /// Remove a presentation property subscription.
    void PropertyChanged(winrt::event_token token) noexcept { changed_.remove(token); }
    /// Publish the properties affected by one state transition on the UI apartment.
    void Notify(std::initializer_list<const wchar_t*> properties) {
        for (const auto property : properties)
            changed_(*static_cast<Derived*>(this), winrt::Microsoft::UI::Xaml::Data::PropertyChangedEventArgs{property});
    }
private:
    winrt::event<winrt::Microsoft::UI::Xaml::Data::PropertyChangedEventHandler> changed_;
};

/// Adapt an existing operation and its availability predicate to a XAML command.
struct ViewModelCommand : winrt::implements<ViewModelCommand, winrt::Microsoft::UI::Xaml::Input::ICommand> {
    /// Capture callbacks whose owners are held through weak references.
    ViewModelCommand(std::function<void()> execute, std::function<bool()> canExecute)
        : execute_(std::move(execute)), canExecute_(std::move(canExecute)) {}
    /// Report whether the operation is currently allowed.
    bool CanExecute(const winrt::Windows::Foundation::IInspectable&) const { return canExecute_(); }
    /// Execute only while the operation remains available.
    void Execute(const winrt::Windows::Foundation::IInspectable&) { if (canExecute_()) execute_(); }
    /// Subscribe to command availability changes.
    winrt::event_token CanExecuteChanged(const winrt::Windows::Foundation::EventHandler<winrt::Windows::Foundation::IInspectable>& handler) {
        return changed_.add(handler);
    }
    /// Remove a command availability subscription.
    void CanExecuteChanged(winrt::event_token token) noexcept { changed_.remove(token); }
    /// Ask bound controls to reevaluate availability after a state transition.
    void Invalidate() { changed_(*this, nullptr); }
private:
    std::function<void()> execute_;
    std::function<bool()> canExecute_;
    winrt::event<winrt::Windows::Foundation::EventHandler<winrt::Windows::Foundation::IInspectable>> changed_;
};
}
