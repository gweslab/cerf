#pragma once

#include "../../jit/guest_cycle_clock.h"

#include <cstdint>

/* SA-1110 Developer's Manual §11.11.3 UTCR0 (printed 11-114): PE 0, SBS 2, DSS 3, SCE 4; §11.11.5
   UTCR3 (printed 11-117): RXE 0, TXE 1, BRK 2, RIE 3, TIE 4, LBM 5. */
namespace sa11xx_uart {
constexpr uint32_t kUtcr0Pe  = 1u << 0;
constexpr uint32_t kUtcr0Sbs = 1u << 2;
constexpr uint32_t kUtcr0Dss = 1u << 3;
constexpr uint32_t kUtcr0Sce = 1u << 4;
constexpr uint32_t kUtcr3Rxe = 1u << 0;
constexpr uint32_t kUtcr3Txe = 1u << 1;
constexpr uint32_t kUtcr3Brk = 1u << 2;
constexpr uint32_t kUtcr3Rie = 1u << 3;
constexpr uint32_t kUtcr3Tie = 1u << 4;
constexpr uint32_t kUtcr3Lbm = 1u << 5;

struct Control {
    uint32_t utcr0 = 0;
    uint32_t utcr1 = 0;
    uint32_t utcr2 = 0;
    uint32_t utcr3 = 0;
};

/* §11.11.4.1 (printed 11-115): "BaudRate = 3.6864x10^6 / (16x(BRD+1))", BRD 11..8 in UTCR1 and
   7..0 in UTCR2. */
constexpr uint64_t kBaudClock = 3686400u;

inline GuestCycleClock::Rate BitRate(uint32_t utcr1, uint32_t utcr2) {
    const uint64_t brd = ((utcr1 & 0xFu) << 8) | (utcr2 & 0xFFu);
    return GuestCycleClock::Rate{kBaudClock, 16u * (brd + 1u)};
}

/* §11.11.1.1: "Each data frame is between 9 bits and 12 bits long": a start bit, 7 or 8 data
   bits, an optional parity bit and one or two stop bits. */
inline uint64_t DataBits(uint32_t utcr0) {
    return (utcr0 & kUtcr0Dss) != 0u ? 8u : 7u;
}

inline uint64_t FrameBits(uint32_t utcr0) {
    return 1u + DataBits(utcr0) + ((utcr0 & kUtcr0Pe) != 0u ? 1u : 0u) +
           ((utcr0 & kUtcr0Sbs) != 0u ? 2u : 1u);
}

/* §11.6.1.1 (printed 11-7): "DA 31:28 = Device port address 31:28", "DA 27:8 = Device port address
   21:2". */
inline uint32_t DeviceAddress(uint32_t utdr) {
    return ((utdr >> 28) << 20) | ((utdr & 0x003FFFFCu) >> 2);
}
}
