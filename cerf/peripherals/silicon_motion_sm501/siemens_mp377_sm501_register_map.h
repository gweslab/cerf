#pragma once

#include "siemens_mp377_sm501.h"

#include <cstdint>

namespace siemens_mp377 {

/* SM501 MMCC Databook v1.02, Tables 2-1, 4-1, 5-1 and 16-1. */
inline bool Sm501IsPlainRegister(uint32_t off) {
    if (off >= 0x080400u && off < 0x081000u && (off & 3u) == 0u) return true;
    switch (off) {
    case 0x000000u:
    case 0x000004u:
    case 0x000008u:
    case 0x00000Cu:
    case 0x000010u:
    case 0x000014u:
    case 0x000030u:
    case 0x000040u:
    case 0x000044u:
    case 0x000048u:
    case 0x00004Cu:
    case 0x000050u:
    case 0x000054u:
    case 0x000058u:
    case 0x00005Cu:
    case 0x000068u:
    case 0x020000u:
    case 0x020004u:
    case 0x020008u:
    case 0x020010u:
    case 0x020014u:
    case 0x020100u:
    case 0x020104u:
    case 0x020108u:
    case 0x020110u:
    case 0x020114u:
    case 0x080000u:
    case 0x080004u:
    case 0x080008u:
    case 0x08000Cu:
    case 0x080010u:
    case 0x080014u:
    case 0x080024u:
    case 0x08002Cu:
    case 0x08005Cu:
    case 0x0800F0u:
    case 0x0800F4u:
    case 0x0800F8u:
    case 0x0800FCu:
    case 0x080200u:
    case 0x080204u:
    case 0x080208u:
    case 0x08020Cu:
    case 0x080210u:
    case 0x080214u:
    case 0x080218u:
    case 0x080230u:
    case 0x080234u:
    case 0x080238u:
    case 0x08023Cu:
    case 0x010000u:
    case 0x010004u:
    case 0x010008u:
    case 0x01000Cu:
    case 0x010010u:
    case 0x010014u:
    case 0x010020u:
    case 0x010024u:
    case 0x010028u:
    case 0x100000u:
    case 0x100004u:
    case 0x100008u:
    case 0x10000Cu:
    case 0x100010u:
    case 0x100014u:
    case 0x100018u:
    case 0x10001Cu:
    case 0x100020u:
    case 0x100024u:
    case 0x100028u:
    case 0x10002Cu:
    case 0x100030u:
    case 0x100034u:
    case 0x100038u:
    case 0x10003Cu:
    case 0x100040u:
    case 0x100044u:
    case 0x100048u:
    case 0x10004Cu:
    case 0x100050u: return true;
    default: return off >= 0x110000u && off < 0x110100u;
    }
}

} // namespace siemens_mp377
