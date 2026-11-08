#pragma once
namespace unlock::components::msi {
inline constexpr wchar_t kCustomActionFile[] = L"UnlockMsiActions.dll";
inline constexpr wchar_t kX64UpgradeCode[] = L"{230B1089-71C8-45EF-A95D-A514CD86E8C8}";
inline constexpr wchar_t kArm64UpgradeCode[] = L"{42E106D8-812F-4941-9E3D-680342FDF426}";
inline constexpr wchar_t kRebootKey[] = L"SOFTWARE\\UnlockWindowsWithIPhone\\MsiRebootRequired";
inline constexpr wchar_t kMaintenanceKey[] = L"SOFTWARE\\UnlockWindowsWithIPhone\\MsiMaintenance";
}
