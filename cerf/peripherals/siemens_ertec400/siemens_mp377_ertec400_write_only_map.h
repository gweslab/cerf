#pragma once

#include "siemens_mp377_ertec400.h"

#include <cstdint>

namespace siemens_mp377 {

inline bool IsErtecPerPortRegister(uint32_t offset, uint32_t base,
                                   uint32_t stride = kErtecSwiPortStride) {
    if (offset < base) return false;
    const uint32_t relative = offset - base;
    return relative % stride == 0u && relative / stride < kErtecSwiPortCount;
}

inline bool IsErtecWriteOnlyRegister(uint32_t offset) {
    if (offset == kErtecIrqMaskLoOffset || offset == kErtecIrqMaskHiOffset) return true;
    if (IsErtecPerPortRegister(offset, kErtecSwiPortFilterBaseOffset, kErtecSwiPortFilterStride)) return true;
    if (IsErtecPerPortRegister(offset, kErtecSwiPhyTimingBaseOffset, kErtecSwiPhyPortStride)) return true;
    if (IsErtecPerPortRegister(offset, kErtecSwiPhyModeBaseOffset, kErtecSwiPhyPortStride)) return true;
    if (IsErtecPerPortRegister(offset, kErtecSwiPhyStatusBaseOffset, kErtecSwiPhyPortStride)) return true;
    if (IsErtecPerPortRegister(offset, kErtecSwiPortVlanBaseOffset)) return true;
    if (IsErtecPerPortRegister(offset, kErtecSwiPortControlBaseOffset)) return true;
    if (IsErtecPerPortRegister(offset, kErtecSwiTraceControlBaseOffset)) return true;

    switch (offset) {
    case kErtecSerPortPresenceMaskOffset:
    case 0x00011000u:
    case 0x00011004u:
    case 0x00011008u:
    case 0x0001100Cu:
    case 0x00011010u:
    case 0x00011014u:
    case 0x00011018u:
    case 0x0001101Cu:
    case 0x00011020u:
    case 0x00011024u:
    case 0x00011028u:
    case 0x00011030u:
    case 0x00011034u:
    case 0x00011038u:
    case 0x00011404u:
    case 0x00011408u:
    case 0x00011410u:
    case 0x0001141Cu:
    case 0x00011424u:
    case 0x00012000u:
    case 0x00012004u:
    case 0x00016000u:
    case 0x00016004u:
    case 0x00016008u:
    case 0x0001600Cu:
    case 0x00016010u:
    case 0x00016014u:
    case 0x00016018u:
    case 0x0001601Cu:
    case 0x00016020u:
    case 0x00016028u:
    case 0x0001602Cu:
    case 0x00016030u:
    case 0x00016034u:
    case 0x00016038u:
    case 0x0001603Cu:
    case 0x00016040u:
    case 0x00016044u:
    case 0x00016410u:
    case 0x00016414u:
    case 0x00016418u:
    case 0x00016420u:
    case 0x00016424u:
    case 0x00016428u:
    case kErtecTraceBufferAddressOffset:
    case kErtecTraceBufferLengthOffset:
    case kErtecTraceEntryCountOffset:
    case 0x00018404u:
    case 0x00019024u:
    case 0x00019028u:
    case 0x0001902Cu:
    case 0x0001903Cu:
    case 0x00019040u:
    case 0x00019044u:
    case 0x00019048u:
    case 0x00019050u:
    case 0x00019054u:
    case kErtecXrtPaddingBaseOffset:
    case kErtecXrtPaddingBaseOffset + 0x04u:
    case kErtecXrtPaddingBaseOffset + 0x08u:
    case kErtecXrtPaddingBaseOffset + 0x0Cu:
    case kErtecXrtStationAddressHiOffset:
    case kErtecXrtStationAddressLoOffset:
    case kErtecIrtStationAddressHiOffset:
    case kErtecIrtStationAddressLoOffset:
    case kErtecAcwBufferAddressOffset:
    case kErtecAcwCountOffset: return true;
    default: return false;
    }
}

} // namespace siemens_mp377
