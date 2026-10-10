// Created by Rui MA on 27 Sep 2026

#pragma once

#include <Windows.h>
#include <credentialprovider.h>

namespace unlock_windows::credential_provider {

// The Setup registers this Credential Provider CLSID.
inline constexpr GUID kUnlockCredentialProviderClsid{
    0x2f7a2df4,
    0x75b4,
    0x4d8e,
    {0x8a, 0x3b, 0x0d, 0xa4, 0x6c, 0x6e, 0x91, 0x12},
};

} // namespace unlock_windows::credential_provider
