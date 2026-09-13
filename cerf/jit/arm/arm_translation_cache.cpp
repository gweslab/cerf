#include "arm_translation_cache.h"

#include <atomic>
#include <cstring>

#include "../../core/cerf_emulator.h"
#include "../../core/log.h"
#include "arm_cpu.h"
#include "arm_mmu.h"
#include "arm_mmu_state.h"
#include "arm_tlb_ops.h"

REGISTER_SERVICE(ArmTranslationCache);

void ArmTranslationCache::PendFlush() {
    flush_pending_ = true;
    std::atomic_ref<uint32_t>(cpu_state_->chain_exit_request)
        .fetch_or(kChainExitFlush, std::memory_order_acq_rel);
}

void ArmTranslationCache::OnReady() {
    mmu_       = &emu_.Get<ArmMmu>();
    cpu_state_ = emu_.Get<ArmCpu>().State();

    arena_.Initialize();

    const ArmMmuState* st = mmu_->State();
    if (st->code_word_top <= st->code_word_base) {
        LOG(Caution, "ArmTranslationCache: board declares no cached-DRAM extent; "
                "the JIT block index has no page window\n");
        CerfFatalExit(CERF_FATAL_RUNTIME_ERROR);
    }
    const uint32_t page_base  = st->code_word_base >> 12;
    const uint32_t page_count = (st->code_word_top - st->code_word_base) >> 12;
    blocks_arm_.Initialize(page_base, page_count);
    blocks_thumb_.Initialize(page_base, page_count);

    LOG(Jit, "ArmTranslationCache::OnReady: arena + %u-page block window at "
            "PA 0x%08X\n", page_count, st->code_word_base);
}

void* ArmTranslationCache::Lookup(bool thumb, uint32_t folded_pc) {
    if (flush_pending_) {
        flush_pending_ = false;
        std::atomic_ref<uint32_t>(cpu_state_->chain_exit_request)
            .fetch_and(~kChainExitFlush, std::memory_order_acq_rel);
        Flush();
    }
    return Space(thumb).JumpCacheLookup(folded_pc);
}

void ArmTranslationCache::Flush() {
    arena_.Flush();
    blocks_arm_.FlushAll();
    blocks_thumb_.FlushAll();
}

void ArmTranslationCache::ContextSwitchFlush() {
    InvalidateVaCachesAll();
}

void ArmTranslationCache::InvalidateVaCachesRange(uint32_t folded_va,
                                                   uint32_t span_bytes) {
    blocks_arm_.JumpCacheClearRange(folded_va, span_bytes);
    blocks_thumb_.JumpCacheClearRange(folded_va, span_bytes);
}

void __fastcall ArmTranslationCache::ContextSwitchFlushHelper(
    ArmTranslationCache* tc) {
    tc->ContextSwitchFlush();
}

void ArmTranslationCache::InvalidateDirtyCodePages() {
    ArmMmuState* st    = mmu_->State();
    uint8_t*     dirty = st->code_page_dirty;
    if (!dirty) return;
    const uint32_t base  = st->code_word_base;
    const uint32_t bytes = st->code_page_dirty_bytes;
    for (uint32_t i = 0; i < bytes; ++i) {
        uint8_t b8 = dirty[i];
        if (!b8) continue;
        dirty[i] = 0;
        for (uint32_t b = 0; b < 8u; ++b) {
            if (!(b8 & (1u << b))) continue;
            const uint32_t page_pa = base + (((i << 3) + b) << 12);
            blocks_arm_.RemoveRange(page_pa, page_pa + 0x0FFFu);
            blocks_thumb_.RemoveRange(page_pa, page_pa + 0x0FFFu);
            const uint32_t word_byte = (page_pa - base) >> 5;
            if (word_byte + 128u <= st->code_word_bitmap_bytes) {
                std::memset(st->code_xlat_bitmap + word_byte, 0, 128u);
            }
        }
    }
}

void __fastcall ArmTranslationCache::InvalidateDirtyCodePagesHelper(
    ArmTranslationCache* tc) {
    tc->InvalidateDirtyCodePages();
}

void __fastcall ArmTranslationCache::ItlbInvalidateAllHelper(
    ArmTranslationCache* tc) {
    ArmTlbFlushAll(&tc->mmu_->State()->instruction_tlb);
    tc->InvalidateVaCachesAll();
}

void __fastcall ArmTranslationCache::DtlbInvalidateAllHelper(
    ArmTranslationCache* tc) {
    ArmTlbFlushAll(&tc->mmu_->State()->data_tlb);
}

void __fastcall ArmTranslationCache::UtlbInvalidateAllHelper(
    ArmTranslationCache* tc) {
    tc->mmu_->InvalidateAllTlbs();
    tc->InvalidateVaCachesAll();
}

/* Rd[7:0] carries an ASID on ARMv6+ (ARM ARM DDI 0406C.c Figure B3-34,
   p. B3-1476); the page-tag match clears the page across every ASID, per
   B3.10.1 (p. B3-1381): "Any TLB operation can affect any other TLB entries
   that are not locked down." */
void __fastcall ArmTranslationCache::ItlbInvalidateMvaHelper(
    uint32_t mva, ArmTranslationCache* tc) {
    ArmMmuState* st = tc->mmu_->State();
    const ArmTlbInvalidation invalidation =
        ArmTlbInvalidateByVa(&st->instruction_tlb, st->process_id, mva);
    tc->InvalidateVaCachesRange(invalidation.base, invalidation.span_bytes);
}

void __fastcall ArmTranslationCache::DtlbInvalidateMvaHelper(
    uint32_t mva, ArmTranslationCache* tc) {
    ArmMmuState* st = tc->mmu_->State();
    ArmTlbInvalidateByVa(&st->data_tlb, st->process_id, mva);
}

void __fastcall ArmTranslationCache::UtlbInvalidateMvaHelper(
    uint32_t mva, ArmTranslationCache* tc) {
    ArmMmuState* st = tc->mmu_->State();
    ArmTlbInvalidateByVa(&st->data_tlb, st->process_id, mva);
    const ArmTlbInvalidation invalidation =
        ArmTlbInvalidateByVa(&st->instruction_tlb, st->process_id, mva);
    tc->InvalidateVaCachesRange(invalidation.base, invalidation.span_bytes);
}
