#pragma once

#include <cstddef>
#include <cstdint>

/* SCTLR / Control Register bit layout. */
union ArmCp15ControlRegister {
    struct {
        uint32_t m         : 1;   /* MMU enable */
        uint32_t a         : 1;   /* alignment check enable */
        uint32_t c         : 1;   /* data cache enable */
        uint32_t w         : 1;   /* write buffer enable */
        uint32_t p         : 1;   /* exception-handler ISA: 0=26-bit, 1=32-bit */
        uint32_t d         : 1;   /* 26/32-bit address checking */
        uint32_t l         : 1;   /* abort model (obsolete) */
        uint32_t b         : 1;   /* big-endian */
        uint32_t s         : 1;   /* system protect */
        uint32_t r         : 1;   /* ROM protect */
        uint32_t reserved2 : 1;
        uint32_t z         : 1;   /* branch target buffer enable */
        uint32_t i         : 1;   /* instruction cache enable */
        uint32_t v         : 1;   /* exception vector relocation (high vectors) */
        uint32_t rr        : 1;   /* cache replacement strategy */
        uint32_t l4        : 1;   /* load instruction bit-0 ignore-Thumb-mode */
        uint32_t reserved3 : 7;   /* bits 16..22 */
        uint32_t xp        : 1;   /* bit 23: 0=subpage AP enabled (v5 fmt),
                                              1=subpage AP disabled (ARMv6 fmt)
                                              ARM1136 TRM Table 3-44 p3-64 */
        uint32_t reserved4 : 8;   /* bits 24..31 */
    } bits;
    uint32_t word;
};
static_assert(sizeof(ArmCp15ControlRegister) == 4, "control register must be 32 bits");

/* ACTLR / Auxiliary Control Register (PXA/ARM-implementation-specific). */
union ArmCp15AuxControlRegister {
    struct {
        uint32_t k         : 1;   /* write coalescing */
        uint32_t p         : 1;   /* page table memory */
        uint32_t reserved1 : 2;
        uint32_t md        : 2;   /* mini data cache */
        uint32_t reserved2 : 26;
    } bits;
    uint32_t word;
};
static_assert(sizeof(ArmCp15AuxControlRegister) == 4, "aux control register must be 32 bits");

/* TTBR / Translation Table Base Register — 16 KB-aligned base of the
   L1 page table; low 14 bits are reserved. */
union ArmCp15TranslationTableBase {
    struct {
        uint32_t reserved1 : 14;
        uint32_t base      : 18;
    } bits;
    uint32_t word;
};
static_assert(sizeof(ArmCp15TranslationTableBase) == 4, "TTBR must be 32 bits");

/* FSR / Fault Status Register. */
union ArmCp15FaultStatus {
    struct {
        uint32_t status   : 4;
        uint32_t domain   : 4;
        uint32_t reserved : 1;
        uint32_t d        : 1;   /* debug event */
        uint32_t x        : 1;   /* status field extension (FS[4] in v7) */
        uint32_t wnr      : 1;   /* v7 write-not-read (ARM DDI 0406B B3.13.4) */
        uint32_t sbz      : 20;
    } bits;
    uint32_t word;
};
static_assert(sizeof(ArmCp15FaultStatus) == 4, "FSR must be 32 bits");

/* FSR.Status codes. */
namespace ArmFaultStatus {
    constexpr uint32_t kVectorException            = 0;
    constexpr uint32_t kAlignment                  = 1;
    constexpr uint32_t kTerminalException          = 2;
    constexpr uint32_t kAlignmentAlt               = 3;
    constexpr uint32_t kExternalAbortLineFetchSection = 4;
    constexpr uint32_t kTranslationSection         = 5;
    constexpr uint32_t kExternalAbortLineFetchPage = 6;
    constexpr uint32_t kTranslationPage            = 7;
    constexpr uint32_t kExternalAbortSection       = 8;
    constexpr uint32_t kDomainSection              = 9;
    constexpr uint32_t kExternalAbortPage          = 10;
    constexpr uint32_t kDomainPage                 = 11;
    constexpr uint32_t kExternalAbortTranslation1  = 12;
    constexpr uint32_t kPermissionSection          = 13;
    constexpr uint32_t kExternalAbortTranslation2  = 14;
    constexpr uint32_t kPermissionPage             = 15;
}

/* Access kind passed to the TLB lookup. The JIT picks ITLB vs DTLB
   based on whether the access is a fetch or a data load/store; read
   vs write distinction further selects permission bits per the AP
   encoding. */
enum class ArmMmuAccess : uint8_t {
    kNone        = 0,
    kRead        = 2,
    kWrite       = 4,
    kReadWrite   = 6,
    kExecute     = 10,
};

/* Direct-mapped 4 KB-granular TLB entry (QEMU softmmu CPUTLBEntry analog): one
   slot per page lets the JIT load/store fast path resolve a host pointer with an
   index + tag compare instead of a per-access call into the page-table walker. */
constexpr uint32_t kArmTlbInvalidTag = 0xFFFFFFFFu;  /* low bits set ⇒ never equals a page-aligned tag */

struct ArmTlbEntry {
    uint32_t  tag;         /* FCSE-folded VA page, or kArmTlbInvalidTag when empty */
    uint32_t  va_addend;   /* host_ptr - foldedVA, so host = foldedVA + va_addend (32-bit host) */
    uint32_t  pa_page;     /* PA & ~0xFFF — store fast path rebuilds PA for the SMC code-dirty check */
    uint8_t   asid;        /* ARM DDI 0406C.c B3.9.1: non-global matches only this CONTEXTIDR[7:0] */
    uint8_t   global;      /* 1 ⇒ matches any ASID */
    uint8_t   writable;    /* 1 ⇒ store fast path eligible (write-permitted + uniform RAM host) */
    uint8_t   pad;
};
static_assert(sizeof(ArmTlbEntry) == 16, "ArmTlbEntry must be 16 bytes for index scaling");

/* N-way set-associative. SA-1110 Dev Man (MMU chapter): "two 32-entry fully
   associative translation buffers" — direct-mapped can't emulate that, so under
   FCSE two processes sharing a low VA collide on the dropped process_id bits,
   evict each other, and hang the demand-pager. Inline probe checks only way 0. */
constexpr uint32_t kArmTlbWays       = 8;
constexpr uint32_t kArmTlbSetBits    = 9;
constexpr uint32_t kArmTlbSets       = 1u << kArmTlbSetBits;       /* 512 */
constexpr uint32_t kArmTlbSetMask    = kArmTlbSets - 1u;
constexpr uint32_t kArmTlbEntryCount = kArmTlbSets * kArmTlbWays;  /* 4096 */
constexpr uint32_t kArmTlbSetShift   = 7;  /* log2(kArmTlbWays * sizeof entry) */
static_assert((1u << kArmTlbSetShift) == kArmTlbWays * sizeof(ArmTlbEntry),
              "set byte-stride shift must match way count * entry size");

/* Set for a VA is entries[ArmTlbSetBase(va) .. +kArmTlbWays); way 0 is MRU. */
struct ArmTlbUnit {
    ArmTlbEntry entries[kArmTlbEntryCount];
};

inline uint32_t ArmTlbSetBase(uint32_t folded_va) {
    return ((folded_va >> 12) & kArmTlbSetMask) * kArmTlbWays;
}

/* Scan a set's ways for a live match. asid is CONTEXTIDR[7:0]; need_write
   requires the way's install-time write permission. Returns the way or -1. */
inline int ArmTlbMatchWay(const ArmTlbUnit* unit, uint32_t base, uint32_t va_page,
                          uint8_t asid, bool need_write) {
    for (uint32_t w = 0; w < kArmTlbWays; ++w) {
        const ArmTlbEntry& e = unit->entries[base + w];
        if (e.tag == va_page && (e.global || e.asid == asid) &&
            (!need_write || e.writable))
            return static_cast<int>(w);
    }
    return -1;
}

/* Move way w to way 0 (MRU) so the way-0-only inline probe finds it next time. */
inline void ArmTlbPromote(ArmTlbUnit* unit, uint32_t base, int w) {
    if (w <= 0) return;
    ArmTlbEntry hit = unit->entries[base + static_cast<uint32_t>(w)];
    for (int i = w; i > 0; --i)
        unit->entries[base + static_cast<uint32_t>(i)] =
            unit->entries[base + static_cast<uint32_t>(i - 1)];
    unit->entries[base] = hit;
}

/* Shift the set down (LRU evict of the last way) and return the freed way-0
   slot for a freshly-walked entry. */
inline ArmTlbEntry& ArmTlbInsertSlot(ArmTlbUnit* unit, uint32_t base) {
    for (uint32_t i = kArmTlbWays - 1; i > 0; --i)
        unit->entries[base + i] = unit->entries[base + i - 1];
    return unit->entries[base];
}

/* Aggregate cp15 + TLB state. The MMU service holds exactly one
   instance; emitted JIT code reads/writes fields by absolute byte
   offset into this struct. */
struct ArmMmuState {
    ArmCp15ControlRegister       control_register;
    ArmCp15AuxControlRegister    aux_control_register;
    ArmCp15TranslationTableBase  translation_table_base;
    uint32_t                     domain_access_control;
    ArmCp15FaultStatus           fault_status;
    uint32_t                     fault_address;
    uint32_t                     process_id;
    uint32_t                     coprocessor_access;

    uint32_t                     cssel_register;

    uint32_t                     ttbr1;        /* c2  CRm=0 op2=1 */
    uint32_t                     ttbcr;        /* c2  CRm=0 op2=2 */
    uint32_t                     prrr;         /* c10 CRm=2 op2=0 */
    uint32_t                     nmrr;         /* c10 CRm=2 op2=1 */
    uint32_t                     contextidr;   /* c13 CRm=0 op2=1 */
    uint32_t                     tpidrurw;     /* c13 CRm=0 op2=2 */
    uint32_t                     tpidruro;     /* c13 CRm=0 op2=3 */
    uint32_t                     tpidrprw;     /* c13 CRm=0 op2=4 */

    ArmTlbUnit                   data_tlb;
    ArmTlbUnit                   instruction_tlb;

    /* SMC code-word marks: 1 bit per 4-byte PA word over [code_word_base,
       code_word_top), set on fetch. DO NOT coarsen below word granularity —
       the kernel packs literal-pool data right after a BX LR, so a coarser
       unit lets a data write false-positive its code page dirty. */
    uint8_t*                     code_xlat_bitmap;
    uint32_t                     code_word_base;
    uint32_t                     code_word_top;
    uint32_t                     code_word_bitmap_bytes;

    /* SMC dirty set, 1 bit per 4 KB PA page over the same extent. A write
       to a marked code word sets its page's bit; the next I-cache invalidate
       invalidates only blocks on dirty pages (targeted, not a whole-cache
       flush — that was the storm). */
    uint8_t*                     code_page_dirty;
    uint32_t                     code_page_dirty_bytes;
};

/* FCSE address fold. When the MMU is enabled and the guest VA is in
   the bottom 32 MB, the high 7 bits are taken from the process ID
   (CONTEXTIDR / FCSEIDR) — so multiple processes each see a private
   0..32 MB slot while the underlying page tables are global. */
inline uint32_t ApplyFcseFold(const ArmMmuState& state, uint32_t va) {
    if (state.control_register.bits.m && (va & 0xFE000000u) == 0u) {
        return va | state.process_id;
    }
    return va;
}
