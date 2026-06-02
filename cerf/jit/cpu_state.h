#pragma once

#include <cstdint>

/* Field byte offsets are baked into JIT-emit sites as immediates;
   reordering or resizing here corrupts every emitted access. MSVC
   bit-field packing (low-to-high) matches the ARM CPSR bit layout. */

/* CPSR view without NZCV. The current NZCV flag bits do NOT live in
   CPSR while the JIT is running — they live in the side x86_flags /
   x86_overflow fields below (lazy flag pack). */
union ArmPsr {
    struct {
        uint32_t mode          : 5;
        uint32_t thumb_mode    : 1;
        uint32_t fiq_disable   : 1;
        uint32_t irq_disable   : 1;
        uint32_t reserved2     : 19;
        uint32_t saturate_flag : 1;
        uint32_t unused        : 4;
    } bits;
    uint32_t partial_word;
};
static_assert(sizeof(ArmPsr) == 4, "ArmPsr must be 32 bits");

/* CPSR view with NZCV explicit — used when packing flags for storage
   or returning CPSR to the kernel. */
union ArmPsrFull {
    struct {
        uint32_t mode          : 5;
        uint32_t thumb_mode    : 1;
        uint32_t fiq_disable   : 1;
        uint32_t irq_disable   : 1;
        uint32_t reserved2     : 19;
        uint32_t saturate_flag : 1;
        uint32_t overflow_flag : 1;
        uint32_t carry_flag    : 1;
        uint32_t zero_flag     : 1;
        uint32_t negative_flag : 1;
    } bits;
    uint32_t word;
};
static_assert(sizeof(ArmPsrFull) == 4, "ArmPsrFull must be 32 bits");

/* Lazy flag pack: ARM NZCV lives here (low-byte layout = x86 EFLAGS,
   Intel SDM Vol. 1 §3.4.3) while JIT runs, NOT in CPSR. */
union ArmX86Flags {
    struct {
        uint32_t carry_flag     : 1;
        uint32_t unused1        : 1;
        uint32_t parity_flag    : 1;
        uint32_t unused2        : 1;
        uint32_t auxiliary_flag : 1;
        uint32_t unused3        : 1;
        uint32_t zero_flag      : 1;
        uint32_t sign_flag      : 1;
        uint32_t unused4        : 24;
    } bits;
    uint8_t  byte;
    uint32_t word;
};

/* x86 OF lives at EFLAGS bit 11, not contiguous with NZ/C in the low
   byte — stored separately. Intel SDM Vol. 1 §3.4.3. */
union ArmX86Overflow {
    uint8_t  byte;
    uint32_t word;
};

/* CPSR flag bit positions (numeric bit indices into a 32-bit CPSR). */
namespace ArmPsrBit {
    constexpr uint32_t kNegative = 31;
    constexpr uint32_t kZero     = 30;
    constexpr uint32_t kCarry    = 29;
    constexpr uint32_t kOverflow = 28;
    constexpr uint32_t kSaturate = 27;
}

/* GPR indices + per-mode bank slot indices for R13/R14. The bank-
   slot constants intentionally collide with R0/R1 — they index the
   2-element gprs_<mode> arrays where slot 0 = R13 for that mode and
   slot 1 = R14. */
namespace ArmGpr {
    constexpr uint32_t kR0  = 0;
    constexpr uint32_t kR1  = 1;
    constexpr uint32_t kR2  = 2;
    constexpr uint32_t kR3  = 3;
    constexpr uint32_t kR4  = 4;
    constexpr uint32_t kR5  = 5;
    constexpr uint32_t kR6  = 6;
    constexpr uint32_t kR7  = 7;
    constexpr uint32_t kR8  = 8;
    constexpr uint32_t kR9  = 9;
    constexpr uint32_t kR10 = 10;
    constexpr uint32_t kR11 = 11;
    constexpr uint32_t kR12 = 12;
    constexpr uint32_t kR13 = 13;
    constexpr uint32_t kR14 = 14;
    constexpr uint32_t kR15 = 15;

    constexpr uint32_t kR13Svc = 0;
    constexpr uint32_t kR14Svc = 1;
    constexpr uint32_t kR13Abt = 0;
    constexpr uint32_t kR14Abt = 1;
    constexpr uint32_t kR13Irq = 0;
    constexpr uint32_t kR14Irq = 1;
    constexpr uint32_t kR13Und = 0;
    constexpr uint32_t kR14Und = 1;
}

/* CPSR.M values. */
namespace ArmMode {
    constexpr uint32_t kUser       = 16;
    constexpr uint32_t kFiq        = 17;
    constexpr uint32_t kIrq        = 18;
    constexpr uint32_t kSupervisor = 19;
    constexpr uint32_t kAbort      = 23;
    constexpr uint32_t kUndefined  = 27;
    constexpr uint32_t kSystem     = 31;
}

/* CPU state. FIQ R8-R12 banking is not modelled — guest software in
   scope does not enable FIQ. */
struct ArmCpuState {
    uint32_t       gprs[16];           /* R0..R15 */
    ArmPsr         cpsr;
    ArmPsrFull     spsr;

    ArmX86Flags    x86_flags;
    ArmX86Overflow x86_overflow;

    uint32_t       gprs_svc[2];        /* R13_svc, R14_svc */
    uint32_t       spsr_svc;

    uint32_t       gprs_abt[2];
    uint32_t       spsr_abt;

    uint32_t       gprs_irq[2];
    uint32_t       spsr_irq;

    uint32_t       gprs_und[2];
    uint32_t       spsr_und;

    /* Emulator-side fields. Polled by the JIT run loop at safe
       boundaries; written from peripheral threads. Aligned uint32_t
       — single-word stores are atomic on x86. */
    uint32_t       irq_interrupt_pending;
    uint32_t       reset_pending;

    uint32_t       ldrex_monitor_addr;
    uint32_t       ldrex_monitor_armed;

    /* VFPv3 / NEON register file. Cortex-A8 has VFPv3-D16 with the
       NEON extension which adds D16..D31 — total 32 doubles = 64
       singles = 16 quads, aliased over the same storage. */
    uint64_t       vfp_d[32];

    /* VFP system registers. */
    uint32_t       fpscr;
    uint32_t       fpexc;
    uint32_t       fpinst;
    uint32_t       fpinst2;

    /* Incremented inline by per-instruction JIT emit (ADD imm8); wraps
       at 2^32. Consumer rebases against frequent polling (kPollInterval
       in Sa1110OsTimer) so cycles between polls are always < 2^32. */
    uint32_t       guest_cycle_counter;

    /* XScale CP0 DSP 40-bit accumulator (acc0); low 40 bits used. Read/
       written by MRA/MAR (MRRC/MCRR p0). Appended last — ArmCpuState
       offsets above are baked into emitted code. */
    uint64_t       acc0;
};
static_assert(sizeof(ArmCpuState) == 432,
              "ArmCpuState layout — JIT emit addresses fields by "
              "absolute byte offset; update emit-site offsets if size "
              "changes.");

/* Per-block FlagsNeeded / FlagsSet tracking masks for the optimiser.
   Bit positions chosen to align with the SETcc-built NZCV nibble in
   the lazy flag pack rather than with CPSR bit positions. */
constexpr uint32_t kFlagN     = 1u << 3;
constexpr uint32_t kFlagZ     = 1u << 2;
constexpr uint32_t kFlagC     = 1u << 1;
constexpr uint32_t kFlagV     = 1u << 0;
constexpr uint32_t kFlagsAll  = kFlagN | kFlagZ | kFlagC | kFlagV;
constexpr uint32_t kFlagsNone = 0;

/* x86 EFLAGS bit positions used by the lazy flag pack. Intel SDM
   Vol. 1 §3.4.3. */
constexpr uint32_t kX86FlagOf = 1u << 0;
constexpr uint32_t kX86FlagNf = 1u << 7;
constexpr uint32_t kX86FlagZf = 1u << 6;
constexpr uint32_t kX86FlagCf = 1u << 0;
