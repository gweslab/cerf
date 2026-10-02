#pragma once

#include <cstdint>

namespace S3C2410TimerRegs {

struct TimerBits {
    int start;
    int manual_update;
    int auto_reload;
};
constexpr TimerBits kTcon[5] = {
    { 0,   1,   3  },
    { 8,   9,   11 },
    { 12,  13,  15 },
    { 16,  17,  19 },
    { 20,  21,  22 },
};

constexpr int kIrqTimerN[5] = { 10, 11, 12, 13, 14 };

constexpr uint32_t kCountMask = 0xFFFFu;

/* S3C2410A UM printed p.10-11 TCFG0 [31:24] reserved, [23:16] dead zone length;
   p.10-12 TCFG1 [31:24] reserved; p.10-13/10-14 TCON output inverters [18] [14]
   [10] [2], dead zone enable [4], [7:5] reserved, no field above [22]. */
constexpr uint32_t kTcfg0DeadZone = 0x00FF0000u;
constexpr uint32_t kTcfgReserved  = 0xFF000000u;
constexpr uint32_t kTconInverters = 0x00044404u;
constexpr uint32_t kTconDeadZone  = 0x00000010u;
constexpr uint32_t kTconReserved  = 0xFF8000E0u;

inline uint32_t Prescaler(int g, uint32_t tcfg0) { return (tcfg0 >> (8 * g)) & 0xFFu; }
inline uint32_t Mux(int n, uint32_t tcfg1) { return (tcfg1 >> (n * 4)) & 0xFu; }
inline uint32_t DividerShift(int n, uint32_t tcfg1) { return Mux(n, tcfg1) + 1u; }

/* S3C2410A UM printed p.10-12 TCFG1 MUX n: 0000 1/2, 0001 1/4, 0010 1/8,
   0011 1/16, 01xx external TCLK. */
inline const char* UnmodelledMux(uint32_t mux) {
    if (mux >= 8u) return "is a code TCFG1 does not define";
    if (mux >= 4u) return "selects external TCLK, which CERF does not model";
    return nullptr;
}
inline uint32_t DmaMode(uint32_t tcfg1) { return (tcfg1 >> 20) & 0xFu; }
inline bool     TconBit(uint32_t tcon, int bit) { return ((tcon >> bit) & 1u) != 0u; }

enum class RegKind { Tcfg0, Tcfg1, Tcon, TcntbN, TcmpbN, TcntoN, OutOfRange };
struct DecodedReg { RegKind kind; int timer_idx; };

inline DecodedReg DecodeReg(uint32_t offset) {
    if (offset == 0x00u) return { RegKind::Tcfg0, 0 };
    if (offset == 0x04u) return { RegKind::Tcfg1, 0 };
    if (offset == 0x08u) return { RegKind::Tcon,  0 };
    /* S3C2410A UM p.10-15: TCNTB0 0x5100000C, TCMPB0 0x51000010,
       TCNTO0 0x51000014; timers 1..3 repeat the triple every 0x0C. */
    for (int i = 0; i < 4; ++i) {
        const uint32_t base = 0x0Cu + 0x0Cu * static_cast<uint32_t>(i);
        if (offset == base + 0u) return { RegKind::TcntbN, i };
        if (offset == base + 4u) return { RegKind::TcmpbN, i };
        if (offset == base + 8u) return { RegKind::TcntoN, i };
    }
    /* S3C2410A UM p.10-19: TCNTB4 0x5100003C and TCNTO4 0x51000040; timer 4
       has no compare buffer. */
    if (offset == 0x3Cu) return { RegKind::TcntbN, 4 };
    if (offset == 0x40u) return { RegKind::TcntoN, 4 };
    return { RegKind::OutOfRange, 0 };
}

}
