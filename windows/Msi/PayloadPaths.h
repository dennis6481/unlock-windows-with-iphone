#pragma once
namespace unlock::components {
inline constexpr wchar_t kPayloadPathComponentPattern[] =
    LR"regex((?!(CON|PRN|AUX|NUL|COM[1-9]|LPT[1-9])(\.|$))[^<>:"/\\|?*\x00-\x1F]*[^<>:"/\\|?*\x00-\x1F. ])regex";
}
