// Created by Rui MA on 16 Oct 2026

#pragma once

#include "PairedDevice.g.h"

namespace winrt::UnlockDesktop::implementation {
struct PairedDevice : PairedDeviceT<PairedDevice> {
    /// Project one paired endpoint into the device list without exposing native objects to the view.
    PairedDevice(hstring id, hstring name) : id_(std::move(id)), name_(std::move(name)) {}
    /// Return the stable Windows association endpoint identifier.
    hstring EndpointId() const { return id_; }
    /// Return the existing display name or its existing unavailable-name text.
    hstring Name() const { return name_.empty() ? hstring{L"Name unavailable"} : name_; }
private:
    hstring id_, name_;
};
}
