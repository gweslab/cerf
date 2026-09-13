#pragma once

#include "../../boards/siemens_mp377/siemens_mp377_panel.h"

#include <cstdint>

namespace siemens_mp377 {

/* SM501 Databook v1.02, PCI Configuration Space Header, BAR0 and BAR1. */
inline constexpr uint32_t kSm501FbBarBus = 0xCA000000u;
inline constexpr uint32_t kSm501FbBytes = 0x01000000u;
inline constexpr uint32_t kSm501RegsBarBus = 0xC8000000u;
inline constexpr uint32_t kSm501RegsBytes = 0x00200000u;

/* Intel 81341/81342 I/O Processors Developer's Manual, sections 2.13.71-2.13.78. */
inline constexpr uint32_t kSm501RegsBarPa = kSm501RegsBarBus;
inline constexpr uint32_t kSm501FbBarPa = kSm501FbBarBus;
inline constexpr uint32_t kSm501RegsCpuStaticPa = 0xC0000000u;

inline bool Sm501BusToOffset(uint32_t pa, uint32_t base, uint32_t bytes, uint32_t& off) {
    if (pa < base) {
        return false;
    }
    off = pa - base;
    return off < bytes;
}

inline bool Sm501FbPaToOffset(uint32_t pa, uint32_t& off) {
    return Sm501BusToOffset(pa, kSm501FbBarPa, kSm501FbBytes, off);
}

inline bool Sm501RegsPaToOffset(uint32_t pa, uint32_t& off) {
    return Sm501BusToOffset(pa, kSm501RegsBarPa, kSm501RegsBytes, off);
}

inline constexpr uint32_t Sm501FbOffsetToPa(uint32_t off) {
    return kSm501FbBarPa + off;
}

inline constexpr uint32_t Sm501RegsOffsetToPa(uint32_t off) {
    return kSm501RegsBarPa + off;
}

static_assert(Sm501FbOffsetToPa(0u) == kSm501FbBarPa, "SM501 BAR0 helper mismatch");
static_assert(Sm501RegsOffsetToPa(0u) == kSm501RegsBarPa, "SM501 BAR1 helper mismatch");

inline constexpr uint32_t kSm501PciVendorId = 0x126Fu;
inline constexpr uint32_t kSm501PciDeviceId = 0x0501u;
inline constexpr uint32_t kSm501PciDeviceVendorDword = (kSm501PciDeviceId << 16) | kSm501PciVendorId;
/* SM501 MMCC Design Guide v1.0, PCI Configuration Space. */
inline constexpr uint32_t kSm501PciCommandStatusDword = 0x0230001Eu;
/* SM501 Databook v1.02, CSR08 PCI Class Code fields. */
inline constexpr uint32_t kSm501PciClassDisplayDword = 0x038000A0u;
inline constexpr uint32_t kSm501PciHeaderTypeDword = 0x00000000u;
/* siemens_mp377_v1040 smibase.dll sub_2B51544/sub_2B5456C;
   VGXaudio.dll sub_2987080. */
inline constexpr uint32_t kSm501PciFbBarFlags = 0x00000000u;
inline constexpr uint32_t kSm501PciRegsBarFlags = 0x00000000u;
inline constexpr uint32_t kSm501PciFbBarDword = kSm501FbBarPa | kSm501PciFbBarFlags;
inline constexpr uint32_t kSm501PciRegsBarDword = kSm501RegsCpuStaticPa | kSm501PciRegsBarFlags;
inline constexpr uint32_t kSm501PciFbBarSizeMask = ~(kSm501FbBytes - 1u);
inline constexpr uint32_t kSm501PciRegsBarSizeMask = ~(kSm501RegsBytes - 1u);
inline constexpr uint32_t kSm501PciInterruptPinIntaLine0Dword = 0x0000010Au;
/* SM501 Databook v1.02 section 3, CSR2C: Subsystem ID and Subsystem
   Vendor ID, power-on default 0x00000000. */
inline constexpr uint32_t kSm501PciSubsystemDword = 0x00000000u;
inline constexpr uint32_t kSm501PciCapabilityPointerDword = 0x00000000u;

inline constexpr uint32_t kSmiBridgeWindowBytes = 0x00000010u;
inline constexpr uint32_t kSmiBridgeBase = 0xC4800028u;
inline constexpr uint32_t kSmiBridgeEnd = kSmiBridgeBase + kSmiBridgeWindowBytes;

inline constexpr uint32_t kFbWidth = kMp377HwiPanel.width;
inline constexpr uint32_t kFbHeight = kMp377HwiPanel.height;
inline constexpr uint32_t kFbStride = kFbWidth * (kMp377HwiPanel.bpp / 8u);

} // namespace siemens_mp377
