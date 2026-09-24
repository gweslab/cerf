#pragma once

#include <cstddef>
#include <cstdint>

/* MIPS (NEC VR5500, MIPS IV, soft-float) CPU state. Once the MIPS engine
   emits against this POD, reordering/resizing corrupts every emitted access. */

namespace MipsCp0 {
    constexpr uint32_t kIndex    = 0;
    constexpr uint32_t kRandom   = 1;
    constexpr uint32_t kEntryLo0 = 2;
    constexpr uint32_t kEntryLo1 = 3;
    constexpr uint32_t kContext  = 4;
    constexpr uint32_t kPageMask = 5;
    constexpr uint32_t kWired    = 6;
    constexpr uint32_t kBadVAddr = 8;
    constexpr uint32_t kCount    = 9;
    constexpr uint32_t kEntryHi  = 10;
    constexpr uint32_t kCompare  = 11;
    constexpr uint32_t kStatus   = 12;
    constexpr uint32_t kCause    = 13;
    constexpr uint32_t kEPC      = 14;
    constexpr uint32_t kPRId     = 15;
    constexpr uint32_t kConfig   = 16;
    constexpr uint32_t kLLAddr   = 17;
    constexpr uint32_t kWatchLo  = 18;
    constexpr uint32_t kWatchHi  = 19;
    constexpr uint32_t kXContext = 20;
    constexpr uint32_t kECC      = 26;
    constexpr uint32_t kTagLo    = 28;
    constexpr uint32_t kTagHi    = 29;
    constexpr uint32_t kErrorEPC = 30;
}

/* CP0 Status bit positions (MIPS R4000 / VR5500). Source: QEMU target/mips
 * cpu.h CP0St_*. The boot value start() writes (0x14410000) sets CU0(28),
 * FR(26), BEV(22) and leaves CU1(29) CLEAR -> FPU disabled (soft-float). */
namespace MipsStatusBit {
    constexpr uint32_t kCU1 = 29;  /* coprocessor-1 (FPU) usable */
    constexpr uint32_t kCU0 = 28;
    constexpr uint32_t kFR  = 26;
    constexpr uint32_t kBEV = 22;  /* bootstrap exception vectors (0xBFC0xxxx) */
    constexpr uint32_t kIM  = 8;   /* interrupt mask IM0..IM7 = bits 8..15 */
    constexpr uint32_t kKSU = 3;   /* KSU mode bits (kernel/supervisor/user) */
    constexpr uint32_t kERL = 2;   /* error level */
    constexpr uint32_t kEXL = 1;   /* exception level */
    constexpr uint32_t kIE  = 0;   /* global interrupt enable */
}

/* CP0 Cause bit positions. Source: QEMU target/mips cpu.h CP0Ca_*. */
namespace MipsCauseBit {
    constexpr uint32_t kBD      = 31; /* last exception taken in a branch delay slot */
    constexpr uint32_t kIV      = 23; /* use special interrupt vector */
    constexpr uint32_t kIP      = 8;  /* pending interrupts IP0..IP7 = bits 8..15 */
    constexpr uint32_t kExcCode = 2;  /* exception code = bits 2..6 */
}

/* CP0 Cause.ExcCode values (MIPS Vol III Table; QEMU tlb_helper.c do_interrupt
   `cause` assignments). Only the ones CERF raises are listed. */
namespace MipsExcCode {
    constexpr uint32_t kInt = 0;   /* interrupt */
    constexpr uint32_t kMod = 1;   /* TLB modified (store to a clean page) */
    constexpr uint32_t kTLBL = 2;  /* TLB miss/invalid on load or fetch */
    constexpr uint32_t kTLBS = 3;  /* TLB miss/invalid on store */
    constexpr uint32_t kAdEL = 4;  /* address error on load/fetch */
    constexpr uint32_t kAdES = 5;  /* address error on store */
    constexpr uint32_t kSys = 8;   /* syscall */
    constexpr uint32_t kBp  = 9;   /* breakpoint */
    constexpr uint32_t kRI  = 10;  /* reserved instruction */
    constexpr uint32_t kOv  = 12;  /* arithmetic overflow */
}

/* Exception vector bases (R4000 / VR5500, pre-Release-2: no writable EBase).
   QEMU do_interrupt: BEV ? exception_base(0xBFC00000)+0x200 : EBase(0x80000000);
   offset 0x000 for a TLB-refill (NOMATCH, EXL was 0), else 0x180. */
namespace MipsExcVector {
    constexpr uint32_t kBaseNormal = 0x80000000u;  /* Status.BEV = 0 */
    constexpr uint32_t kBaseBev    = 0xBFC00200u;  /* Status.BEV = 1 */
    constexpr uint32_t kOffRefill  = 0x000u;       /* TLB refill (TLBL/TLBS, NOMATCH, !EXL) */
    constexpr uint32_t kOffGeneral = 0x180u;       /* all other exceptions */
}

constexpr uint32_t kMipsNumGpr     = 32;

/* Branch/delay-slot carry kind = QEMU hflags branch field (cpu.h
   MIPS_HFLAG_B/BC/BL/BR); set by the branch, read after the delay slot. */
namespace MipsBranch {
    constexpr uint32_t kNone       = 0;
    constexpr uint32_t kUncond     = 1;  /* MIPS_HFLAG_B  - j / jal */
    constexpr uint32_t kCond       = 2;  /* MIPS_HFLAG_BC - beq/bne/bgtz/blez/bltz/bgez */
    constexpr uint32_t kRegister   = 3;  /* MIPS_HFLAG_BR - jr / jalr */
    constexpr uint32_t kCondLikely = 4;  /* MIPS_HFLAG_BL - *L: not-taken nullifies delay slot */
}

/* One R4000-style TLB entry. Source: QEMU target/mips internal.h r4k_tlb_t;
   VR5500 omits MMID/XI/RI/EHINV. pfn halves are masked & <<12 (r4k_fill_tlb). */
struct MipsTlbEntry {
    uint32_t vpn;        /* CP0_EntryHi & (TARGET_PAGE_MASK<<1) - the VPN2 tag */
    uint32_t page_mask;  /* CP0_PageMask */
    uint16_t asid;       /* CP0_EntryHi & ASID (VR5500: 0xFF) */
    uint8_t  g;          /* global: EntryLo0 & EntryLo1 & 1 */
    uint8_t  v0, d0, c0; /* even page: valid / dirty / cache attr (bits 5:3) */
    uint8_t  v1, d1, c1; /* odd page */
    uint8_t  pad[7];
    uint64_t pfn[2];     /* even/odd physical frame */
};

/* QEMU mips-defs.h:5 MIPS_TLB_MAX = 128: the tlb[] array bound. The live joint
   entry count (nb_tlb) is a per-SoC fact from MipsProcessorConfig::TlbSize()
   seeded into MipsCpuState::nb_tlb; [nb_tlb, tlb_in_use) hold tlbwr shadows. */
constexpr uint32_t kMipsTlbMax = 128;

struct MipsCpuState {
    /* GPRs are 64-bit: VR5500 is a 64-bit MIPS IV core and the kernel uses
       genuine 64-bit values (e.g. memset builds a 64-bit fill via dsll32/daddu
       and stores it with sd). 32-bit ALU ops sign-extend their result into the
       full register; logical/doubleword ops are full-width. r0 reads as 0. */
    uint64_t gpr[kMipsNumGpr];
    uint64_t hi;                 /* MULT/DIV/DMULT/DDIV result high */
    uint64_t lo;                 /* MULT/DIV/DMULT/DDIV result low */
    uint32_t pc;                 /* current guest PC (32-bit addressing) */

    /* Branch/delay-slot carry (QEMU gen_compute_branch:4382, gen_branch:10949,
       save_cpu_state:1280). A branch sets these, NOT pc, and they persist across
       blocks so a branch at a page's last word resolves in the next block. */
    uint32_t branch_state;       /* MipsBranch::kNone/kUncond/kCond/kRegister */
    uint32_t btarget;            /* target VA (uncond/cond) or gpr[rs] (register) */
    uint32_t bcond;              /* cond: computed condition 0/1, read at resolve */

    /* CP0 system-control registers CE drives + the kernel reads. */
    uint32_t cp0_index;
    uint32_t cp0_random;
    uint32_t cp0_entrylo0;
    uint32_t cp0_entrylo1;
    uint32_t cp0_context;
    uint32_t cp0_pagemask;
    uint32_t cp0_wired;
    uint32_t cp0_badvaddr;
    uint32_t cp0_count;
    uint32_t cp0_entryhi;
    uint32_t cp0_compare;
    uint32_t cp0_status;
    uint32_t cp0_cause;
    uint32_t cp0_epc;
    uint32_t cp0_prid;
    uint32_t cp0_config;
    uint32_t cp0_watchlo;        /* CP0 WatchLo (present iff MipsProcessorConfig::HasWatch) */
    uint32_t cp0_watchhi;        /* CP0 WatchHi */
    uint32_t cp0_taglo;          /* CP0 TagLo (r28) cache-tag; no cache modeled (CACHE=NOP) -> plain R/W */
    uint32_t cp0_taghi;          /* CP0 TagHi (r29) cache-tag */
    uint32_t cp0_errorepc;
    uint32_t cp0_lladdr;         /* CP0 LLAddr (r17); VR4102 UM 5.5.7 R/W, "serves no function" (no LL/SC) -> plain R/W */
    uint32_t cp0_xcontext;       /* CP0 XContext (r20); UM 6.3.9 R/W, only the 64-bit XTLB refill reads it (CE 2.0 is 32-bit) -> plain R/W */
    uint32_t cp0_ecc;            /* CP0 ECC/PErr (r26); UM 6.3.10 R/W cache-parity diag; no cache modeled -> plain R/W */

    /* Software-managed TLB (guest kernel owns page tables; CERF never walks
       them). Faithful QEMU r4k: [0,nb_tlb) live + [nb_tlb,tlb_in_use) shadow. */
    MipsTlbEntry tlb[kMipsTlbMax];
    uint32_t     nb_tlb;       /* live joint-TLB entry count (MipsProcessorConfig::TlbSize) */
    uint32_t     tlb_in_use;   /* = nb_tlb at reset (QEMU cpu.c:291) */

    /* LL/SC: LL records the linked address + arms llbit; a conflicting store
     * clears llbit; SC succeeds iff llbit still set. */
    uint32_t llbit;
    uint32_t ll_addr;

    uint32_t reset_pending;
    uint32_t deep_sleep;
    uint32_t guest_cycle_counter;

    /* In-core R4000 Count/Compare timer (the CE scheduler tick = IP7 on this
       pre-R2 core). Count is driven off guest_cycle_counter on the JIT thread;
       count_anchor is the cycle value at the last advance, timer_armed gates a
       single IP7 raise per Compare write (QEMU cp0_timer.c). */
    uint32_t count_anchor;
    uint32_t timer_armed;

    /* log2(min TLB page size) from MipsProcessorConfig::MinPageShift(), seeded
       at reset like nb_tlb. MipsMmu derives the PFN shift / PageMask alignment /
       VPN2 width from it (VR5500 12, VR4102 10). */
    uint32_t min_page_shift;

    /* AND-mask for a TLB-translated PA, from MipsProcessorConfig::PhysAddrMask()
       (VR4102 0x1FFFFFFF physical mirror; VR5500 0xFFFFFFFF). */
    uint32_t phys_addr_mask;

    /* MIPS16 ISA mode bit (VR4100 Series UM U15509EJ2V0UM 3.4): 0 = 32-bit
       instructions only, 1 = MIPS16 only. Changed by JALX/JR/JALR (3.4.1),
       cleared on exception entry with the prior mode saved to EPC/ErrorEPC
       bit 0 (3.4.2), cleared by cold/soft reset (ibid.). */
    uint32_t isa_mode;

    /* ISA mode the pending branch target executes in, applied with btarget at
       delay-slot resolve: JR/JALR take it from bit 0 of the source register,
       JALX inverts the current mode, every other branch keeps it (UM 3.4.1). */
    uint32_t btarget_isa;

    /* Pending branch/jump byte length; delay-slot EPC = slot PC - branch_len
       (QEMU exception.c exception_resume_pc:41, MIPS_HFLAG_B16 ? 2 : 4). */
    uint32_t branch_len;
};

static_assert(offsetof(MipsTlbEntry, pfn) == 24, "MipsTlbEntry layout");
static_assert(sizeof(MipsTlbEntry) == 40, "MipsTlbEntry layout");
static_assert(sizeof(MipsCpuState) == 5560, "MipsCpuState layout");

/* CP0 register number -> byte offset of its field in MipsCpuState, or -1 for a
   register CERF does not model. Shared by the MFC0 (read) and MTC0 (write) place
   fns so the reg->field map exists once. */
inline int32_t Cp0RegOffset(uint32_t rd) {
    switch (rd) {
        case MipsCp0::kIndex:    return static_cast<int32_t>(offsetof(MipsCpuState, cp0_index));
        case MipsCp0::kRandom:   return static_cast<int32_t>(offsetof(MipsCpuState, cp0_random));
        case MipsCp0::kEntryLo0: return static_cast<int32_t>(offsetof(MipsCpuState, cp0_entrylo0));
        case MipsCp0::kEntryLo1: return static_cast<int32_t>(offsetof(MipsCpuState, cp0_entrylo1));
        case MipsCp0::kContext:  return static_cast<int32_t>(offsetof(MipsCpuState, cp0_context));
        case MipsCp0::kPageMask: return static_cast<int32_t>(offsetof(MipsCpuState, cp0_pagemask));
        case MipsCp0::kWired:    return static_cast<int32_t>(offsetof(MipsCpuState, cp0_wired));
        case MipsCp0::kBadVAddr: return static_cast<int32_t>(offsetof(MipsCpuState, cp0_badvaddr));
        case MipsCp0::kCount:    return static_cast<int32_t>(offsetof(MipsCpuState, cp0_count));
        case MipsCp0::kEntryHi:  return static_cast<int32_t>(offsetof(MipsCpuState, cp0_entryhi));
        case MipsCp0::kCompare:  return static_cast<int32_t>(offsetof(MipsCpuState, cp0_compare));
        case MipsCp0::kStatus:   return static_cast<int32_t>(offsetof(MipsCpuState, cp0_status));
        case MipsCp0::kCause:    return static_cast<int32_t>(offsetof(MipsCpuState, cp0_cause));
        case MipsCp0::kEPC:      return static_cast<int32_t>(offsetof(MipsCpuState, cp0_epc));
        case MipsCp0::kPRId:     return static_cast<int32_t>(offsetof(MipsCpuState, cp0_prid));
        case MipsCp0::kConfig:   return static_cast<int32_t>(offsetof(MipsCpuState, cp0_config));
        case MipsCp0::kWatchLo:  return static_cast<int32_t>(offsetof(MipsCpuState, cp0_watchlo));
        case MipsCp0::kWatchHi:  return static_cast<int32_t>(offsetof(MipsCpuState, cp0_watchhi));
        case MipsCp0::kTagLo:    return static_cast<int32_t>(offsetof(MipsCpuState, cp0_taglo));
        case MipsCp0::kTagHi:    return static_cast<int32_t>(offsetof(MipsCpuState, cp0_taghi));
        case MipsCp0::kErrorEPC: return static_cast<int32_t>(offsetof(MipsCpuState, cp0_errorepc));
        case MipsCp0::kLLAddr:   return static_cast<int32_t>(offsetof(MipsCpuState, cp0_lladdr));
        case MipsCp0::kXContext: return static_cast<int32_t>(offsetof(MipsCpuState, cp0_xcontext));
        case MipsCp0::kECC:      return static_cast<int32_t>(offsetof(MipsCpuState, cp0_ecc));
        default:                 return -1;
    }
}

/* True iff MTC0 may write this register. PRId is read-only silicon; Random is
   the hardware free-running index; BadVAddr is set by the fault path - all three
   are MFC0-readable but not MTC0-writable. */
inline bool Cp0RegWritable(uint32_t rd) {
    return rd != MipsCp0::kPRId && rd != MipsCp0::kRandom && rd != MipsCp0::kBadVAddr;
}

/* MIPS TLB VPN2 geometry from the min-page shift S (MipsCpuState::min_page_shift):
   the VPN2 pair spans 2^(S+1); EntryHi/Context VPN2 = VA[31:S+1] (VR4102 UM 5.2.2
   1 KB S=10; R4000 4 KB S=12). One definition shared by the MMU, the TLB-refill
   CP0 setup, and the MTC0-EntryHi mask so the VPN2 field has a single meaning. */
inline uint32_t MipsPairMinMask(uint32_t s) { return (1u << (s + 1u)) - 1u; }
inline uint32_t MipsVpn2Mask(uint32_t s)    { return ~MipsPairMinMask(s); }
