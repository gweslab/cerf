#pragma once

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
    constexpr uint32_t kExtendedSmallPage = 3;   /* 1 KB  */
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

    /* L1 entry mapping a 1 MB section. */
    struct {
        uint32_t type         : 2;   /* must be 2 */
        uint32_t b            : 1;
        uint32_t c            : 1;
        uint32_t reserved1    : 1;
        uint32_t domain       : 4;
        uint32_t p            : 1;
        uint32_t ap           : 2;
        uint32_t tex          : 4;
        uint32_t reserved2    : 4;
        uint32_t section_base : 12;
    } section;

    /* L1 entry pointing at an L2 fine page table. */
    struct {
        uint32_t type             : 2;   /* must be 3 */
        uint32_t reserved1        : 3;
        uint32_t domain           : 4;
        uint32_t p                : 1;
        uint32_t reserved2        : 2;
        uint32_t page_table_base  : 18;
    } fine;
};
static_assert(sizeof(ArmL1Pte) == 4, "L1 PTE must be 32 bits");

union ArmL2Pte {
    uint32_t word;

    struct {
        uint32_t type : 2;
        uint32_t sbz  : 30;
    } fault;

    /* 64 KB large page. APs field carries four 2-bit AP values, one
       per 16 KB sub-page, selected by VA[15:14]. */
    struct {
        uint32_t type             : 2;   /* must be 1 */
        uint32_t b                : 1;
        uint32_t c                : 1;
        uint32_t aps              : 8;
        uint32_t tex              : 4;
        uint32_t large_page_base  : 16;
    } large_page;

    /* 4 KB small page. APs field carries four 2-bit AP values, one
       per 1 KB sub-page, selected by VA[11:10]. */
    struct {
        uint32_t type             : 2;   /* must be 2 */
        uint32_t b                : 1;
        uint32_t c                : 1;
        uint32_t aps              : 8;
        uint32_t small_page_base  : 20;
    } small_page;

    /* 1 KB extended small page. Single 2-bit AP covers the whole
       page. */
    struct {
        uint32_t type                     : 2;   /* must be 3 */
        uint32_t b                        : 1;
        uint32_t c                        : 1;
        uint32_t ap                       : 2;
        uint32_t tex                      : 4;
        uint32_t extended_small_page_base : 22;
    } extended_small_page;
};
static_assert(sizeof(ArmL2Pte) == 4, "L2 PTE must be 32 bits");

/* ARM1136 TRM Table 6-16 / Fig 6-5: 4 KB extended small page (coarse-L2
   type=3 with SCTLR.XP=0) — PA = base[31:12] | VA[11:0]. */
inline uint32_t ArmExtSmallPagePa(uint32_t pte_word, uint32_t va) {
    return (pte_word & 0xFFFFF000u) | (va & 0x0FFFu);
}
