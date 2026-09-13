#pragma once

#include <cstdint>

namespace siemens_mp377 {

/* siemens_mp377_v1040 bspio.dll HWI_PNIO_GetInfo: family 4 variants
   1/2/4/8; nk.exe sub_80446E14: family 4, variant 2 = 800x600x16. */
enum class SiemensMp377PanelProfile {
    Inch12_800x600,
    Inch15_1024x768,
    Inch19_1280x1024,
};

struct SiemensMp377PanelDescriptor {
    SiemensMp377PanelProfile profile;
    uint8_t op_type_family;
    uint8_t op_type_variant;
    uint32_t width;
    uint32_t height;
    uint32_t bpp;
};

inline constexpr SiemensMp377PanelDescriptor Mp377PanelDescriptor(SiemensMp377PanelProfile p) {
    return p == SiemensMp377PanelProfile::Inch12_800x600    ? SiemensMp377PanelDescriptor{p, 4u, 2u, 800u, 600u, 16u}
           : p == SiemensMp377PanelProfile::Inch15_1024x768 ? SiemensMp377PanelDescriptor{p, 4u, 4u, 1024u, 768u, 16u}
                                                            : SiemensMp377PanelDescriptor{p, 4u, 8u, 1280u, 1024u, 16u};
}

inline constexpr SiemensMp377PanelProfile kMp377HwiPanelProfile = SiemensMp377PanelProfile::Inch12_800x600;
inline constexpr SiemensMp377PanelDescriptor kMp377HwiPanel = Mp377PanelDescriptor(kMp377HwiPanelProfile);

inline constexpr uint32_t Mp377PanelWidth(SiemensMp377PanelProfile p) {
    return Mp377PanelDescriptor(p).width;
}

inline constexpr uint32_t Mp377PanelHeight(SiemensMp377PanelProfile p) {
    return Mp377PanelDescriptor(p).height;
}

} // namespace siemens_mp377
