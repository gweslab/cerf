#include "arm_mmu.h"

#include "../cpu/arm_processor_config.h"
#include "../cpu/emulated_memory.h"
#include "arm_pte.h"

/* Side-effect-free VA->host peek: no TLB fill, no abort raise. Diagnostic /
   tracing use only. */
uint8_t* ArmMmu::PeekVaToHost(uint32_t va) {
    uint32_t p = va;

    /* MMU off: VA == PA (as MapGuestVirtualToHost's M==0 path). */
    if (!state_.control_register.bits.m) {
        uint8_t* ram = memory_->TryTranslateWrite(p);
        return ram ? ram : memory_->TryTranslate(p);
    }

    /* FCSE fold: low-32-MB VAs are private to the current process,
       same fold MapGuestVirtualToHost applies. */
    if ((p & 0xFE000000u) == 0u) p |= state_.process_id;

    /* TTBR0/TTBR1 selection, same as MapGuestVirtualToHost's walk. */
    const uint32_t ttbcr_n    = state_.ttbcr & 7u;
    const uint32_t ttbr0_mask = ~((1u << (14u - ttbcr_n)) - 1u);
    const bool use_ttbr1 = ttbcr_n != 0u && (p >> (32u - ttbcr_n)) != 0u;
    const uint32_t l1_base = use_ttbr1
        ? (state_.ttbr1 & 0xFFFFC000u)
        : (state_.translation_table_base.word & ttbr0_mask);

    const uint32_t l1_pa = l1_base | ((p >> 20) << 2);
    uint8_t* l1_host = memory_->TryTranslateWrite(l1_pa);
    if (!l1_host) return nullptr;
    ArmL1Pte l1_pte;
    l1_pte.word = *reinterpret_cast<uint32_t*>(l1_host);

    uint32_t effective_address;
    switch (l1_pte.fault.type) {
    case ArmL1PteType::kSection:
        effective_address = (l1_pte.section.section_base << 20) | (p & 0x000FFFFFu);
        break;

    case ArmL1PteType::kCoarse: {
        const uint32_t l2_pa = (l1_pte.coarse.page_table_base << 10)
                             | (((p >> 12) & 0xFFu) << 2);
        uint8_t* l2_host = memory_->TryTranslateWrite(l2_pa);
        if (!l2_host) return nullptr;
        ArmL2Pte l2_pte;
        l2_pte.word = *reinterpret_cast<uint32_t*>(l2_host);

        const bool v6_ext_small = processor_config_->HasCp15V6() &&
                                  !state_.control_register.bits.xp;
        if (l2_pte.fault.type == ArmL2PteType::kSmallPage) {
            effective_address = (l2_pte.small_page.small_page_base << 12) | (p & 0x0FFFu);
        } else if (l2_pte.fault.type == ArmL2PteType::kExtendedSmallPage && v6_ext_small) {
            effective_address = ArmExtSmallPagePa(l2_pte.word, p);
        } else {
            /* Large page / fault / v5-1KB extended small — caller does software. */
            return nullptr;
        }
        break;
    }

    default:
        /* kFault / kFine — caller does software. */
        return nullptr;
    }

    /* PA -> host: writable RAM, then flash/read-only; I/O PA -> nullptr,
       same resolution order as MapGuestVirtualToHost's kRead path. */
    uint8_t* ram = memory_->TryTranslateWrite(effective_address);
    if (ram) return ram;
    return memory_->TryTranslate(effective_address);
}
