#include "mips_mmu.h"

#include "../isa_block_space.h"
#include "../../state/state_stream.h"

uint32_t MipsMmu::NextRandom(uint32_t first, uint32_t nb) {
    if (nb == 1) {
        return first;
    }
    uint32_t idx;
    do {
        lcg_seed_ = 1103515245u * lcg_seed_ + 12345u;
        idx = (lcg_seed_ >> 16) % nb + first;
    } while (idx == prev_random_idx_);
    prev_random_idx_ = idx;
    return idx;
}

void MipsMmu::FlushAll(MipsCpuState* st) {
    /* cpu_mips_tlb_flush (tlb_helper.c:492): flush the host translation cache +
       discard all shadow entries. */
    blocks32_->JumpCacheFlush();
    blocks16_->JumpCacheFlush();
    st->tlb_in_use = st->nb_tlb;
}

void MipsMmu::JumpCacheClearPage(uint32_t page_va) {
    blocks32_->JumpCacheClearPage(page_va);
    blocks16_->JumpCacheClearPage(page_va);
}

void MipsMmu::SaveState(StateWriter& w) const {
    w.Write("lcg_seed", lcg_seed_);
    w.Write("prev_random_idx", prev_random_idx_);
}

void MipsMmu::RestoreState(StateReader& r) {
    r.Read("lcg_seed", lcg_seed_);
    r.Read("prev_random_idx", prev_random_idx_);
}
