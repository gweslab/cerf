#pragma once

#include <cstdint>
#include <vector>

enum class ArmMmuAccess : uint32_t {
    kRead,
    kWrite,
    kReadWrite,
    kExecute,
};

/* ARM DDI 0406C.c B3.19.2 FCSETranslate (p. B3-1503): "if va<31:25> ==
   '0000000' then mva = FCSEIDR.PID:va<24:0>", with no SCTLR.M term.
   process_id holds FCSEIDR.PID:'0'*25, so the concatenation is an OR. */
inline uint32_t ArmFcseFold(uint32_t va, uint32_t process_id) {
    return (va & 0xFE000000u) == 0u ? (va | process_id) : va;
}

/* SCTLR bit positions: ARM DDI 0406C.c B4.1.130 (VMSAv7), D12.7.4
   (VMSAv6 diagram), D15.7 (ARMv4/v5). */
union ArmSctlr {
    uint32_t word;

    struct {
        uint32_t m           : 1;   /* [0] MMU enable */
        uint32_t a           : 1;   /* [1] alignment check enable */
        uint32_t c           : 1;   /* [2] data cache enable */
        uint32_t w           : 1;   /* [3] write buffer enable (v4/v5) */
        uint32_t rao_6_4     : 3;   /* [6:4] RAO */
        uint32_t b           : 1;   /* [7] BE-32 endianness (v4/v5) */
        uint32_t s           : 1;   /* [8] System protection (Table D15-7) */
        uint32_t r           : 1;   /* [9] ROM protection (Table D15-7) */
        uint32_t f           : 1;   /* [10] v5 F; v7 SW */
        uint32_t z           : 1;   /* [11] branch prediction enable */
        uint32_t i           : 1;   /* [12] instruction cache enable */
        uint32_t v           : 1;   /* [13] Vectors: 0 low, 1 Hivecs */
        uint32_t rr          : 1;   /* [14] round-robin cache replacement */
        uint32_t l4          : 1;   /* [15] v5 L4 */
        uint32_t reserved_20 : 5;   /* [20:16] */
        uint32_t fi          : 1;   /* [21] fast interrupts */
        uint32_t u           : 1;   /* [22] unaligned access model */
        uint32_t xp          : 1;   /* [23] VMSAv6/v7 vs legacy v4/v5
                                       translation format (D12.7.4) */
        uint32_t ve          : 1;   /* [24] interrupt vectors enable */
        uint32_t ee          : 1;   /* [25] exception endianness */
        uint32_t l2          : 1;   /* [26] v6 L2 */
        uint32_t nmfi        : 1;   /* [27] non-maskable FIQ */
        uint32_t tre         : 1;   /* [28] TEX remap enable */
        uint32_t afe         : 1;   /* [29] access flag enable */
        uint32_t te          : 1;   /* [30] Thumb exception enable */
        uint32_t reserved_31 : 1;   /* [31] */
    } bits;
};
static_assert(sizeof(ArmSctlr) == 4);

/* DFSR, Short-descriptor format (ARM DDI 0406C.c B4.1.52): FS[3:0]
   [3:0], Domain [7:4], [8] Reserved UNK/SBZP, LPAE [9], FS[4] [10],
   WnR [11], ExT [12], CM [13]. */
union ArmDfsr {
    uint32_t word;

    struct {
        uint32_t status       : 4;   /* FS[3:0] */
        uint32_t domain       : 4;   /* [7:4] */
        uint32_t reserved_8_9 : 2;   /* [8] UNK/SBZP, [9] LPAE */
        uint32_t fs4          : 1;   /* [10] FS[4] */
        uint32_t wnr          : 1;   /* [11] Write not Read */
        uint32_t ext          : 1;   /* [12] external abort type */
        uint32_t cm           : 1;   /* [13] cache maintenance */
        uint32_t reserved     : 18;  /* [31:14] */
    } bits;
};
static_assert(sizeof(ArmDfsr) == 4);

/* ARM DDI 0406C.c B4.1.154: table base at [31:14-N], N = TTBCR.N
   (B4.1.153 bits[2:0]). */
struct ArmTtbr0 {
    uint32_t word;
};

/* ARM DDI 0406C.c Table B3-23, Short-descriptor FS encodings. Every
   value used here has FS[4] = 0, so ArmDfsr.bits.status holds it whole. */
namespace ArmFaultStatus {
    /* ARM DDI 0406C.c Table B3-23: synchronous external abort. */
    constexpr uint32_t kExternalAbort               = 0b01000;
    constexpr uint32_t kAlignment                   = 0b00001;
    constexpr uint32_t kTranslationSection          = 0b00101;
    constexpr uint32_t kTranslationPage             = 0b00111;
    constexpr uint32_t kDomainSection               = 0b01001;
    constexpr uint32_t kDomainPage                  = 0b01011;
    constexpr uint32_t kPermissionSection           = 0b01101;
    constexpr uint32_t kPermissionPage              = 0b01111;
    constexpr uint32_t kExternalAbortTranslation1   = 0b01100;
    constexpr uint32_t kExternalAbortTranslation2   = 0b01110;
}

struct ArmTlbEntry {
    uint32_t tag;
    uint32_t va_addend;
    uint32_t pa_page;
    uint8_t  asid;        /* CONTEXTIDR[7:0] (ARM DDI 0406C.c B4.1.36) */
    uint8_t  global;
    uint8_t  writable;
    uint8_t  span_shift;
};
static_assert(sizeof(ArmTlbEntry) == 16,
              "emit_tlb_fast_path.cpp addresses ways at stride 16");

constexpr uint32_t kArmTlbWays       = 4;
constexpr uint32_t kArmTlbSets       = 256;
constexpr uint32_t kArmTlbSetMask    = kArmTlbSets - 1u;
constexpr uint32_t kArmTlbSetShift   = 6;
constexpr uint32_t kArmTlbIoTagBit   = 1u;
constexpr uint32_t kArmTlbInvalidTag = 0xFFFFFFFFu;
constexpr uint32_t kArmSectionShift  = 20u;
constexpr uint32_t kArmSectionCount  = 1u << (32u - kArmSectionShift);
static_assert((kArmTlbWays * sizeof(ArmTlbEntry)) == (1u << kArmTlbSetShift),
              "emit_tlb_fast_path.cpp computes a set's byte offset as "
              "set << kArmTlbSetShift");

constexpr uint32_t kArmTlbEntryCount = kArmTlbSets * kArmTlbWays;
constexpr uint32_t kArmTlbSpanBitWords = kArmTlbEntryCount / 32u;
constexpr uint32_t kArmTlbRegionBitWords = kArmSectionCount / 32u;

struct ArmTlbSpanTracker {
    uint16_t region_refs[kArmSectionCount]{};
    uint32_t entry_bits[kArmTlbSpanBitWords]{};
    uint32_t active_region_bits[kArmTlbRegionBitWords]{};
    std::vector<uint16_t> active_regions;
};

struct ArmTlbUnit {
    ArmTlbEntry entries[kArmTlbSets * kArmTlbWays];
    ArmTlbSpanTracker* span_tracker = nullptr;
};

inline uint32_t ArmTlbSetBase(uint32_t va) {
    return ((va >> 12) & kArmTlbSetMask) * kArmTlbWays;
}

inline int ArmTlbMatchWay(const ArmTlbUnit* unit, uint32_t base,
                          uint32_t tag, uint8_t asid, bool need_write) {
    for (uint32_t w = 0; w < kArmTlbWays; ++w) {
        const ArmTlbEntry& e = unit->entries[base + w];
        if (e.tag != tag) continue;
        if (!e.global && e.asid != asid) continue;
        if (need_write && !e.writable) continue;
        return static_cast<int>(w);
    }
    return -1;
}

inline int ArmTlbMatchIoWay(const ArmTlbUnit* unit, uint32_t base,
                            uint32_t page_tag, uint8_t asid,
                            bool need_write) {
    return ArmTlbMatchWay(unit, base, page_tag | kArmTlbIoTagBit,
                          asid, need_write);
}

inline bool ArmTlbEntryIsWideSpan(const ArmTlbEntry& entry) {
    return entry.tag != kArmTlbInvalidTag && entry.span_shift > 12u;
}

static_assert(kArmTlbWays <= 32u && (kArmTlbWays & (kArmTlbWays - 1u)) == 0u,
              "a set's span bits must occupy one aligned field of entry_bits");

inline uint32_t ArmTlbSpanBitField(uint32_t base) {
    return ((1u << kArmTlbWays) - 1u) << (base & 31u);
}

inline void ArmTlbPromote(ArmTlbUnit* unit, uint32_t base, int way) {
    if (way <= 0) return;
    const ArmTlbEntry hit = unit->entries[base + static_cast<uint32_t>(way)];
    for (int w = way; w > 0; --w) {
        unit->entries[base + static_cast<uint32_t>(w)] =
            unit->entries[base + static_cast<uint32_t>(w - 1)];
    }
    unit->entries[base] = hit;
    ArmTlbSpanTracker* tracker = unit->span_tracker;
    if (!tracker) return;
    uint32_t& bits = tracker->entry_bits[base >> 5];
    const uint32_t rotated_field =
        ((1u << (static_cast<uint32_t>(way) + 1u)) - 1u) << (base & 31u);
    const uint32_t live = bits & rotated_field;
    if (live == 0u) return;
    bits = (bits & ~rotated_field) |
           (((live << 1) | (live >> static_cast<uint32_t>(way))) & rotated_field);
}

inline ArmTlbEntry& ArmTlbInsertSlot(ArmTlbUnit* unit, uint32_t base) {
    for (uint32_t w = kArmTlbWays - 1u; w > 0; --w) {
        unit->entries[base + w] = unit->entries[base + w - 1u];
    }
    return unit->entries[base];
}

struct ArmMmuState {
    /* ARM DDI 0406C.c B3.15.5 (p. B3-1461): a direct write "must be
       synchronized before any instruction that appears after the direct
       write ... can rely on the effect of that write"; the same section
       exempts direct reads of the same register using the same encoding. */
    ArmSctlr  control_register{};
    ArmSctlr  effective_control_register{};
    uint32_t  aux_control_register  = 0;
    ArmTtbr0  translation_table_base{};
    uint32_t  domain_access_control = 0;   /* DACR (B4.1.43) */
    ArmDfsr   fault_status{};
    uint32_t  fault_address         = 0;
    uint32_t  ifsr                  = 0;   /* IFSR: FS[3:0], no Domain/WnR
                                              (B4.1.96, short-descriptor) */
    uint32_t  ifar                  = 0;   /* IFAR (B4.1.95) */
    uint32_t  process_id            = 0;   /* FCSEIDR.PID:'0'*25, ORed over
                                              va<24:0> per ARM DDI 0406C.c
                                              B3.19.2 FCSETranslate */
    /* ARM DDI 0406C.c D10.1.1 / DDI 0100I B4.2.3: the FCSE PID "is SBZ when
       the MMU is disabled", and "Behavior is UNPREDICTABLE if the FCSE PID is
       not zero when the MMU is disabled". Kept by ArmMmu::RefreshFcseFold. */
    uint32_t  fcse_fold_id          = 0;
    uint32_t  coprocessor_access    = 0;   /* CPACR */
    uint32_t  cssel_register        = 0;   /* CSSELR */
    uint32_t  ttbr1                 = 0;
    uint32_t  ttbcr                 = 0;   /* N = bits[2:0] (B4.1.153) */
    uint32_t  prrr                  = 0;
    uint32_t  nmrr                  = 0;
    uint32_t  contextidr            = 0;   /* ASID = [7:0] (B4.1.36) */
    uint32_t  tpidrurw              = 0;
    uint32_t  tpidruro              = 0;
    uint32_t  tpidrprw              = 0;
    uint32_t  l2_aux_control        = 0;   /* ARM DDI 0344 §3.2.55 */

    ArmTlbUnit data_tlb{};
    ArmTlbUnit instruction_tlb{};

    uint32_t code_word_base         = 0;
    uint32_t code_word_top          = 0;
    uint32_t code_word_bitmap_bytes = 0;
    uint8_t* code_xlat_bitmap       = nullptr;
    uint32_t code_page_dirty_bytes  = 0;
    uint8_t* code_page_dirty        = nullptr;

    template <typename F>
    static constexpr void Visit(ArmMmuState& s, F& field) {
        field("control_register", s.control_register.word);
        field("effective_control_register", s.effective_control_register.word);
        field("aux_control_register", s.aux_control_register);
        field("translation_table_base", s.translation_table_base.word);
        field("domain_access_control", s.domain_access_control);
        field("fault_status", s.fault_status.word);
        field("fault_address", s.fault_address);
        field("ifsr", s.ifsr);
        field("ifar", s.ifar);
        field("process_id", s.process_id);
        field.Skip(s.fcse_fold_id);
        field("coprocessor_access", s.coprocessor_access);
        field("cssel_register", s.cssel_register);
        field("ttbr1", s.ttbr1);
        field("ttbcr", s.ttbcr);
        field("prrr", s.prrr);
        field("nmrr", s.nmrr);
        field("contextidr", s.contextidr);
        field("tpidrurw", s.tpidrurw);
        field("tpidruro", s.tpidruro);
        field("tpidrprw", s.tpidrprw);
        field("l2_aux_control", s.l2_aux_control);
        field.Skip(s.data_tlb);
        field.Skip(s.instruction_tlb);
        field.Skip(s.code_word_base);
        field.Skip(s.code_word_top);
        field.Skip(s.code_word_bitmap_bytes);
        field.Skip(s.code_xlat_bitmap);
        field.Skip(s.code_page_dirty_bytes);
        field.Skip(s.code_page_dirty);
    }
};

template <ArmMmuAccess kAccess>
inline void ArmNoteCodeTracking(ArmMmuState& st, uint32_t pa) {
    if (pa < st.code_word_base || pa >= st.code_word_top) return;
    const uint32_t off = pa - st.code_word_base;
    if constexpr (kAccess == ArmMmuAccess::kExecute) {
        const uint32_t w0 = off >> 2;
        const uint32_t w1 = (off + 3u) >> 2;
        st.code_xlat_bitmap[w0 >> 3] |= static_cast<uint8_t>(1u << (w0 & 7u));
        st.code_xlat_bitmap[w1 >> 3] |= static_cast<uint8_t>(1u << (w1 & 7u));
    } else if constexpr (kAccess == ArmMmuAccess::kWrite ||
                         kAccess == ArmMmuAccess::kReadWrite) {
        const uint32_t w = off >> 2;
        if (st.code_xlat_bitmap[w >> 3] & (1u << (w & 7u))) {
            const uint32_t page = off >> 12;
            st.code_page_dirty[page >> 3] |=
                static_cast<uint8_t>(1u << (page & 7u));
        }
    }
}
