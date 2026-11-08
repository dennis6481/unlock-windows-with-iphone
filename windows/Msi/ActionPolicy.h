#pragma once
#include "../SavedCredential/SavedCredentialIpc.h"

namespace unlock::components::msi {
enum class Operation { firstInstall, maintain, upgradeRemoval, remove };
constexpr Operation operation(bool installed, bool removing, bool upgrading, bool existing) {
    return removing ? (upgrading ? Operation::upgradeRemoval : Operation::remove)
        : installed || existing ? Operation::maintain : Operation::firstInstall;
}
constexpr bool maintenanceAllowed(bool system, bool nativeMsi, unlock_windows::saved_credential::Operation value) {
    return system && nativeMsi && value == unlock_windows::saved_credential::Operation::clearForRemoval;
}
}
