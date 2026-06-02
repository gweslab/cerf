#include "arm_jit.h"

#include <cstring>

#include "../core/cerf_emulator.h"
#include "arm_mmu.h"
#include "arm_mmu_state.h"

/* JIT translation invalidation: context-switch (VA-keyed native caches) and
   SMC (targeted phys-page block removal). */

void ArmJit::ContextSwitchFlush() {
    blocks_arm_.JumpCacheFlush();
    blocks_thumb_.JumpCacheFlush();
    /* Shadow-stack entries cache (folded return VA → native); on FCSE PID
       reuse the folded key collides with the new process, so drop them. */
    shadow_stack_count_ = 0;
}

void __fastcall ArmJit::ContextSwitchFlushHelper(ArmJit* jit) {
    jit->ContextSwitchFlush();
}

void ArmJit::InvalidateDirtyCodePages() {
    ArmMmuState* st    = mmu_->State();
    uint8_t*     dirty = st->code_page_dirty;
    if (!dirty) return;
    const uint32_t base  = st->code_word_base;
    const uint32_t bytes = st->code_page_dirty_bytes;
    bool any = false;
    for (uint32_t i = 0; i < bytes; ++i) {
        uint8_t b8 = dirty[i];
        if (!b8) continue;
        dirty[i] = 0;
        for (uint32_t b = 0; b < 8u; ++b) {
            if (!(b8 & (1u << b))) continue;
            const uint32_t page_pa = base + (((i << 3) + b) << 12);
            blocks_arm_.RemoveRange(page_pa, page_pa + 0x0FFFu);
            blocks_thumb_.RemoveRange(page_pa, page_pa + 0x0FFFu);
            /* Clear this page's code-word marks so it stays clean until code
               re-executes — else a mixed code+data page re-dirties on every
               data write and thrashes. 4 KB page = 1024 words = 128 bitmap
               bytes at (page-offset >> 5). */
            const uint32_t word_byte = (page_pa - base) >> 5;
            if (word_byte + 128u <= st->code_word_bitmap_bytes) {
                std::memset(st->code_xlat_bitmap + word_byte, 0, 128u);
            }
            any = true;
        }
    }
    if (any) {
        /* Removed blocks' jump-cache slots were already cleared per-block in
           RemoveRange (keeps the rest of the cache warm). Reset the shadow
           stack (small; can't cheaply per-entry clear) so a pending return
           can't pop a stale native into a removed block. */
        shadow_stack_count_ = 0;
    }
}

void __fastcall ArmJit::InvalidateDirtyCodePagesHelper(ArmJit* jit) {
    jit->InvalidateDirtyCodePages();
}
