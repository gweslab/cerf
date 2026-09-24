#pragma once

#include <array>
#include <cstdint>

/* Intel MCS-51 Programmer's Guide, Table 1; siemens_mp377_v1040 SM501
   firmware CODE:0030/0033/0036/0100. */
namespace sm501_8051 {

inline constexpr uint8_t kSfrSp = 0x81u;
inline constexpr uint8_t kSfrDpl = 0x82u;
inline constexpr uint8_t kSfrDph = 0x83u;
inline constexpr uint8_t kSfrIe = 0xA8u;
inline constexpr uint8_t kSfrPsw = 0xD0u;
inline constexpr uint8_t kSfrAcc = 0xE0u;
inline constexpr uint8_t kSfrB = 0xF0u;

/* siemens_mp377_v1040 SM501 8051 firmware CODE:0030/0033/003B/0043. */
inline constexpr uint8_t kSfrEie = 0xE8u;
inline constexpr uint8_t kSfrEip = 0xF8u;

/* MCS-51 Programmer's Guide, PSW: CY 7, AC 6, F0 5, RS1 4, RS0 3, OV 2,
   user flag 1, P 0. */
inline constexpr uint8_t kPswCarry = 1u << 7;
inline constexpr uint8_t kPswAuxCarry = 1u << 6;
inline constexpr uint8_t kPswRs1 = 1u << 4;
inline constexpr uint8_t kPswRs0 = 1u << 3;
inline constexpr uint8_t kPswOverflow = 1u << 2;
inline constexpr uint8_t kPswParity = 1u << 0;

/* MCS-51 Programmer's Guide, IE: EA 7, ES 4, ET1 3, EX1 2, ET0 1, EX0 0.  The
   firmware reaches only EA, through bit address 0AFh. */
inline constexpr uint8_t kIeGlobal = 1u << 7;

/* MCS-51 Hardware Description, How Interrupts Are Handled,
   Source/Vector Address table. */
inline constexpr uint16_t kVectorExtendedBase = 0x0033u;
inline constexpr uint16_t kVectorStride = 8u;

/* MCS-51 Hardware Description, Interrupt Priorities. */
inline constexpr uint8_t kInServiceLow = 1u << 0;
inline constexpr uint8_t kInServiceHigh = 1u << 1;

struct State {
    uint16_t pc = 0u;
    std::array<uint8_t, 256> iram{};

    uint8_t acc = 0u;
    uint8_t b = 0u;
    uint8_t psw = 0u;
    uint8_t sp = 0x07u;
    uint8_t dpl = 0u;
    uint8_t dph = 0u;
    uint8_t ie = 0u;

    uint8_t eie = 0u;
    uint8_t eip = 0u;

    uint8_t extended_pending = 0u;

    uint8_t in_service = 0u;

    /* MCS-51 Hardware Description, How Interrupts Are Handled, condition 3. */
    bool block_next_vector = false;
    uint8_t pad[2] = {};

    uint64_t executed = 0u;

    template <typename F>
    static constexpr void Visit(State& s, F& field) {
        field("pc", s.pc);
        field("iram", s.iram);
        field("acc", s.acc);
        field("b", s.b);
        field("psw", s.psw);
        field("sp", s.sp);
        field("dpl", s.dpl);
        field("dph", s.dph);
        field("ie", s.ie);
        field("eie", s.eie);
        field("eip", s.eip);
        field("extended_pending", s.extended_pending);
        field("in_service", s.in_service);
        field("block_next_vector", s.block_next_vector);
        field.Skip(s.pad);
        field("executed", s.executed);
    }
};

}  // namespace sm501_8051
