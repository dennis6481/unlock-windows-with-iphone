#pragma once

namespace unlock::components::msi {
enum class Operation { firstInstall, maintain, remove };
constexpr Operation operation(bool installed, bool removing, bool existing) {
    return removing ? Operation::remove
        : installed || existing ? Operation::maintain : Operation::firstInstall;
}
}
