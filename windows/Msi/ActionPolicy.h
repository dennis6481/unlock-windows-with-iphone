#pragma once

namespace unlock::components::msi {
enum class Operation { firstInstall, maintain, upgradeRemoval, remove };
constexpr Operation operation(bool installed, bool removing, bool upgrading, bool existing) {
    return removing ? (upgrading ? Operation::upgradeRemoval : Operation::remove)
        : installed || existing ? Operation::maintain : Operation::firstInstall;
}
}
