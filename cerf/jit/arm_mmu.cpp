#include "arm_mmu.h"

#include "../boards/page_table_builder.h"
#include "../core/cerf_emulator.h"
#include "../cpu/arm_processor_config.h"
#include "../cpu/emulated_memory.h"
#include "arm_pte.h"
#include "arm_tlb_ops.h"

REGISTER_SERVICE(ArmMmu);

ArmMmu::~ArmMmu() = default;

void ArmMmu::OnReady() {
    memory_           = &emu_.Get<EmulatedMemory>();
    processor_config_ = &emu_.Get<ArmProcessorConfig>();

    /* SMC word-bitmap spans the board's DRAM PA extent only: code is
       writable (hence self-modifiable) solely in DRAM, so a write outside
       this range can never invalidate a translation. */
    uint32_t dram_min = 0xFFFFFFFFu;
    uint32_t dram_max = 0u;
    for (const auto& r : emu_.Get<PageTableBuilder>().CachedDramRegions()) {
        if (r.pa_base < dram_min)          dram_min = r.pa_base;
        if (r.pa_base + r.size > dram_max) dram_max = r.pa_base + r.size;
    }
    state_.code_word_base         = dram_min;
    state_.code_word_top          = dram_max;
    state_.code_word_bitmap_bytes =
        (dram_max > dram_min) ? (((dram_max - dram_min) >> 2) + 7u) / 8u : 0u;

    code_xlat_bitmap_storage_.assign(state_.code_word_bitmap_bytes, 0u);
    state_.code_xlat_bitmap = code_xlat_bitmap_storage_.data();

    state_.code_page_dirty_bytes =
        (dram_max > dram_min) ? (((dram_max - dram_min) >> 12) + 7u) / 8u : 0u;
    code_page_dirty_storage_.assign(state_.code_page_dirty_bytes, 0u);
    state_.code_page_dirty = code_page_dirty_storage_.data();

    ArmTlbFlushAll(&state_.data_tlb);
    ArmTlbFlushAll(&state_.instruction_tlb);
}

uint32_t __fastcall ArmMmu::CcsidrLookupHelper(ArmMmu* mmu) {
    /* cp15 c0 op1=1 CRm=0 op2=0 (CCSIDR), indexed by CSSELR.
       Reference: QEMU helper.c:942-947, cpu.h:1131-1134. */
    return mmu->emu_.Get<ArmProcessorConfig>().Ccsidr(mmu->state_.cssel_register);
}

void ArmMmu::RaiseAbort(uint32_t va, uint32_t fault_status, bool is_write) {
    state_.fault_status.bits.status = fault_status;
    state_.fault_status.bits.d      = 0;
    state_.fault_status.bits.x      = 1;
    state_.fault_status.bits.wnr    = is_write ? 1u : 0u;
    state_.fault_address             = va;
}

void ArmMmu::RaiseAlignmentFault(uint32_t va) {
    state_.fault_status.bits.status = ArmFaultStatus::kAlignment;
    state_.fault_status.bits.d      = 0;
    state_.fault_status.bits.x      = 0;
    state_.fault_address            = va;
}

void ArmMmu::SetIoPending(uint32_t pa) {
    if (pa == 0u) {
        /* Encode PA-0 as (4, -4) so the io_pa sentinel is naturally
           aligned to every access size (byte/halfword/word) — the
           JIT-side alignment check tests low bits of EAX(=io_pa);
           a sentinel of 1 would falsely fail. Real PA = 4 + (-4) = 0. */
        io_pending_address_        = 4u;
        io_pending_address_adjust_ = static_cast<uint32_t>(-4);
    } else {
        io_pending_address_        = pa;
        io_pending_address_adjust_ = 0u;
    }
}


std::optional<uint8_t*> ArmMmu::PeekDataTlb(uint32_t va) const {
    /* Diagnostic-only: never walks, never raises, never mutates TLB state.
       Returns a host pointer only on a direct-mapped fast-TLB hit. */
    uint32_t p = va;
    if (state_.control_register.bits.m && (p & 0xFE000000u) == 0u) {
        p |= state_.process_id;
    }
    const uint8_t current_asid = static_cast<uint8_t>(state_.contextidr & 0xFFu);
    const uint32_t base = ArmTlbSetBase(p);
    const int w = ArmTlbMatchWay(&state_.data_tlb, base, p & 0xFFFFF000u,
                                 current_asid, /*need_write=*/false);
    if (w >= 0) {
        const ArmTlbEntry& e = state_.data_tlb.entries[base + static_cast<uint32_t>(w)];
        return reinterpret_cast<uint8_t*>(static_cast<uintptr_t>(p) + e.va_addend);
    }
    return std::nullopt;
}

bool ArmMmu::ExecPageGlobal(uint32_t va) const {
    /* va is already FCSE-folded by the caller (JitCreateEntrypoints passes the
       decoded insn's actual_guest_address). Absent ⇒ false: claiming global for
       an evicted user (nG=1) page would route its block into the shared global
       tree where another process would execute it. */
    const uint8_t current_asid = static_cast<uint8_t>(state_.contextidr & 0xFFu);
    const uint32_t base = ArmTlbSetBase(va);
    const int w = ArmTlbMatchWay(&state_.instruction_tlb, base,
                                 va & 0xFFFFF000u, current_asid,
                                 /*need_write=*/false);
    return w >= 0 &&
           state_.instruction_tlb.entries[base + static_cast<uint32_t>(w)].global != 0u;
}
