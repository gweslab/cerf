#include "isa_block_space.h"

void IsaBlockSpace::JumpCacheClearRange(uint32_t base_va,
                                        uint32_t span_bytes) {
    if (span_bytes == 0x1000u) {
        JumpCacheClearPage(base_va);
        return;
    }
    for (JumpCacheEntry& e : jump_cache) {
        const uint32_t page = e.folded_va & 0xFFFFF000u;
        if (page - base_va < span_bytes) {
            e.folded_va = 0;
            e.native    = nullptr;
            e.blk       = nullptr;
        }
    }
}
