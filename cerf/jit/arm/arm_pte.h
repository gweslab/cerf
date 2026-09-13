#pragma once

#include "../../cpu/arm_processor_config.h"

#include <cstdint>

/* L1 PTE type values (bits[1:0] of the PTE word). */
namespace ArmL1PteType {
    constexpr uint32_t kFault   = 0;
    constexpr uint32_t kCoarse  = 1;   /* L1 entry points at an L2 coarse page table */
    constexpr uint32_t kSection = 2;   /* L1 entry maps a 1 MB section directly */
    constexpr uint32_t kFine    = 3;   /* L1 entry points at an L2 fine page table */
}

/* L2 PTE type values (bits[1:0] of the PTE word). */
namespace ArmL2PteType {
    constexpr uint32_t kFault             = 0;
    constexpr uint32_t kLargePage         = 1;   /* 64 KB */
    constexpr uint32_t kSmallPage         = 2;   /* 4 KB  */
    constexpr uint32_t kExtendedSmallPage = 3;   /* coarse table: 4 KB
                                                    (ARM DDI 0406C.c Table D15-9) */
    constexpr uint32_t kTinyPage          = 3;   /* fine table: 1 KB
                                                    (ARM DDI 0406C.c Table D15-10) */
}

union ArmL1Pte {
    uint32_t word;

    struct {
        uint32_t type : 2;
        uint32_t sbz  : 30;
    } fault;

    /* L1 entry pointing at an L2 coarse page table. */
    struct {
        uint32_t type             : 2;   /* must be 1 */
        uint32_t reserved1        : 3;
        uint32_t domain           : 4;
        uint32_t p                : 1;
        uint32_t page_table_base  : 22;
    } coarse;

    /* 1 MB Section (ARM DDI 0406C.c Figure B3-4; the ARMv4/v5 layout in
       Table D15-8 leaves [4] and [19:15] SBZ). */
    struct {
        uint32_t pxn          : 1;   /* [0] SBZ without the PXN attribute */
        uint32_t one          : 1;   /* [1] must be 1 */
        uint32_t b            : 1;   /* [2] */
        uint32_t c            : 1;   /* [3] */
        uint32_t xn           : 1;   /* [4] */
        uint32_t domain       : 4;   /* [8:5] */
        uint32_t p            : 1;   /* [9] IMPLEMENTATION DEFINED */
        uint32_t ap           : 2;   /* [11:10] AP[1:0] */
        uint32_t tex          : 3;   /* [14:12] TEX[2:0] */
        uint32_t ap2          : 1;   /* [15] AP[2] */
        uint32_t s            : 1;   /* [16] */
        uint32_t ng           : 1;   /* [17] */
        uint32_t zero_18      : 1;   /* [18] 0 = Section, 1 = Supersection */
        uint32_t ns           : 1;   /* [19] */
        uint32_t section_base : 12;  /* [31:20] PA[31:20] */
    } section;

    /* L1 Fine page table descriptor (ARM DDI 0406C.c Table D15-8:
       bits[31:12] give the second-level table's physical address;
       fine tables are 4 KB aligned). */
    struct {
        uint32_t type             : 2;   /* [1:0] must be 3 */
        uint32_t sbz_4_2          : 3;
        uint32_t domain           : 4;   /* [8:5] */
        uint32_t p                : 1;   /* [9] */
        uint32_t sbz_11_10        : 2;
        uint32_t page_table_base  : 20;  /* [31:12] */
    } fine;
};
static_assert(sizeof(ArmL1Pte) == 4, "L1 PTE must be 32 bits");

union ArmL2Pte {
    uint32_t word;

    struct {
        uint32_t type : 2;
        uint32_t sbz  : 30;
    } fault;

    /* 64 KB Large page. ARMv4/v5 (ARM DDI 0406C.c Table D15-9): AP0 [5:4],
       AP1 [7:6], AP2 [9:8], AP3 [11:10] - the AP bits for subpages 0..3,
       subpage 0 lowest-addressed; TEX [14:12], [15] SBZ. VMSAv7
       (Figure B3-5): AP[1:0] [5:4], AP[2] [9], S [10], nG [11], XN [15]. */
    struct {
        uint32_t type             : 2;   /* [1:0] must be 1 */
        uint32_t b                : 1;   /* [2] */
        uint32_t c                : 1;   /* [3] */
        uint32_t ap0              : 2;   /* [5:4] */
        uint32_t ap1              : 2;   /* [7:6] */
        uint32_t ap2              : 2;   /* [9:8] */
        uint32_t ap3              : 2;   /* [11:10] */
        uint32_t tex              : 3;   /* [14:12] TEX[2:0] */
        uint32_t xn               : 1;   /* [15] */
        uint32_t large_page_base  : 16;  /* [31:16] PA[31:16] */
    } large_page;

    /* 4 KB Small page (ARM DDI 0406C.c Table D15-9): AP0 [5:4], AP1 [7:6],
       AP2 [9:8], AP3 [11:10] - the AP bits for subpages 0..3, subpage 0
       lowest-addressed. */
    struct {
        uint32_t type             : 2;   /* [1:0] must be 2 */
        uint32_t b                : 1;   /* [2] */
        uint32_t c                : 1;   /* [3] */
        uint32_t ap0              : 2;   /* [5:4] */
        uint32_t ap1              : 2;   /* [7:6] */
        uint32_t ap2              : 2;   /* [9:8] */
        uint32_t ap3              : 2;   /* [11:10] */
        uint32_t small_page_base  : 20;  /* [31:12] PA[31:12] */
    } small_page;

    /* 1 KB Tiny page (ARM DDI 0406C.c Table D15-10): single AP at [5:4],
       SBZ [9:6], base PA[31:10]. */
    struct {
        uint32_t type           : 2;   /* [1:0] must be 3 */
        uint32_t b              : 1;   /* [2] */
        uint32_t c              : 1;   /* [3] */
        uint32_t ap             : 2;   /* [5:4] */
        uint32_t sbz_9_6        : 4;   /* [9:6] */
        uint32_t tiny_page_base : 22;  /* [31:10] */
    } tiny_page;
};
static_assert(sizeof(ArmL2Pte) == 4, "L2 PTE must be 32 bits");

struct ArmSectionTranslation {
    uint64_t physical_address;
    uint32_t span_bytes;
    uint32_t domain;
};

/* ARM DDI 0100I B4.7.5 and Table B4-2. */
inline ArmSupersectionFormat ArmEffectiveSupersectionFormat(ArmSupersectionFormat format,
                                                            bool extended_format) {
    return format == ArmSupersectionFormat::kArmV6 && !extended_format
        ? ArmSupersectionFormat::kNone
        : format;
}

/* ARM DDI 0406C.c B3.5.4 and B4.1.154: TTBR selection and L1 index. */
inline uint32_t ArmL1DescriptorAddress(uint32_t va, uint32_t ttbcr,
                                       uint32_t ttbr0, uint32_t ttbr1) {
    const uint32_t n = ttbcr & 7u;
    const uint32_t ttbr0_mask = ~((1u << (14u - n)) - 1u);
    const bool use_ttbr1 = n != 0u && (va >> (32u - n)) != 0u;
    const uint32_t base = use_ttbr1 ? (ttbr1 & 0xFFFFC000u)
                                    : (ttbr0 & ttbr0_mask);
    return base | ((va >> 20) << 2);
}

/* Intel Third Generation XScale Microarchitecture Developer's Manual
   section 3.2.2.1, Table 14 and Figure 2; ARM DDI 0406C.d Figure B3-4. */
inline ArmSectionTranslation ArmTranslateSection(uint32_t pte_word, uint32_t va,
                                                 ArmSupersectionFormat format) {
    const bool supersection = format != ArmSupersectionFormat::kNone && ((pte_word >> 18) & 1u) != 0u;
    if (supersection) {
        uint64_t high = static_cast<uint64_t>(pte_word & 0x00F00000u) << 12;
        if (format == ArmSupersectionFormat::kArmV6 ||
            format == ArmSupersectionFormat::kArmV7) {
            high |= static_cast<uint64_t>(pte_word & 0x000001E0u) << 31;
        }
        const uint64_t low = static_cast<uint64_t>((pte_word & 0xFF000000u) |
                                                   (va & 0x00FFFFFFu));
        return {high | low, 0x01000000u, 0u};
    }
    return {static_cast<uint64_t>((pte_word & 0xFFF00000u) |
                                  (va & 0x000FFFFFu)),
            0x00100000u,
            (pte_word >> 5) & 0x0Fu};
}

/* ARM1136 TRM Table 6-16 / Fig 6-5: 4 KB extended small page (coarse-L2
   type=3 with SCTLR.XP=0) - PA = base[31:12] | VA[11:0]. */
inline uint32_t ArmExtSmallPagePa(uint32_t pte_word, uint32_t va) {
    return (pte_word & 0xFFFFF000u) | (va & 0x0FFFu);
}

/* ARM DDI 0406C.c Tables D15-9/D15-10 place AP0..AP3 at [5:4]..[11:10];
   p. D15-2609 "Subpage support": APn is the AP field for subpage n of
   four equal subpages, subpage 0 lowest-addressed. */
inline uint32_t ArmL2SubpageAp(const ArmL2Pte& pte, uint32_t subpage) {
    switch (subpage & 3u) {
        case 0:  return pte.small_page.ap0;
        case 1:  return pte.small_page.ap1;
        case 2:  return pte.small_page.ap2;
        default: return pte.small_page.ap3;
    }
}
