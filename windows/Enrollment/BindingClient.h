// Created by Rui MA on 11 Oct 2026

#pragma once

#include "../SavedCredential/SavedCredentialIpc.h"
#include <string_view>
#include <functional>

namespace unlock_windows::enrollment {
saved_credential::BindingSummary readBinding();
winrt::handle createCancellation(const std::wstring& sid, std::wstring& name);
DWORD launchHelper(const std::wstring& arguments, bool elevated, const std::function<void()>& update = {});
void manageBinding(saved_credential::Operation operation, const saved_credential::SensitiveBytes& payload);
int runBindingHelper(std::wstring_view operation, std::wstring_view hex);
}
