#pragma once

#include <cstdint>
#include <cstring>
#include <vector>

#include "jit_block_index.h"

/* VA-indexed jump cache (QEMU tb_jmp_cache). Keyed by FCSE-folded VA; the
   block index itself is phys-keyed. Flushed on context switch / SMC / full
   flush so a stale VA→native mapping never survives an address-space change. */
constexpr uint32_t kJumpCacheSize = 4096;

constexpr uint32_t kBlockUnindexed = 0xFFFFFFFFu;
struct JumpCacheEntry {
    uint32_t  folded_va;
    void*     native;
    /* QEMU cpu-exec.c tb_lookup: a tb_jmp_cache hit is validated against the
       TB before use. */
    JitBlock* blk;
    uint32_t  reserved;
};

constexpr uint32_t kJumpCacheEntryShift = 4;
static_assert(sizeof(JumpCacheEntry) == (1u << kJumpCacheEntryShift),
              "emitted jump-cache probes scale the index by a shift");

/* Per-ISA blocks. CE7 sets FCSE process_id=0, so the index key no
   longer separates address spaces - partition by ASID: global (nG=0
   kernel/shared) shared across processes; user (nG=1) in per_asid. */
struct IsaBlockSpace {
    JitBlockIndex global;
    JitBlockIndex per_asid[256];
    uint32_t      asid_populated[8] = {0};
    JumpCacheEntry jump_cache[kJumpCacheSize];

    /* Per-physical-page intrusive list of outer blocks (QEMU
       PageDesc.first_tb), sized over the DRAM page extent. */
    std::vector<JitBlock*> page_heads;
    uint32_t               page_base  = 0;
    uint32_t               page_count = 0;

    void JumpCacheFlush() { std::memset(jump_cache, 0, sizeof(jump_cache)); }

    /* QEMU tb_jmp_cache_clear_page (accel/tcg/cputlb.c:150). */
    void JumpCacheClearPage(uint32_t page_va) {
        const uint32_t base = page_va & 0xFFFFF000u;
        for (uint32_t off = 0; off < 0x1000u; off += 4u) {
            JumpCacheEntry& e =
                jump_cache[((base + off) >> 2) & (kJumpCacheSize - 1u)];
            if ((e.folded_va & 0xFFFFF000u) == base) {
                e.folded_va = 0;
                e.native    = nullptr;
                e.blk       = nullptr;
            }
        }
    }

    void JumpCacheClearRange(uint32_t base_va, uint32_t span_bytes);

    void* JumpCacheLookup(uint32_t folded_va) const {
        const JumpCacheEntry& e = jump_cache[(folded_va >> 2) & (kJumpCacheSize - 1u)];
        return e.folded_va == folded_va ? e.native : nullptr;
    }

    const JumpCacheEntry* JumpCacheProbe(uint32_t folded_va) const {
        const JumpCacheEntry& e = jump_cache[(folded_va >> 2) & (kJumpCacheSize - 1u)];
        return e.folded_va == folded_va ? &e : nullptr;
    }

    void JumpCacheInsert(uint32_t folded_va, void* native,
                         JitBlock* blk = nullptr) {
        JumpCacheEntry& e = jump_cache[(folded_va >> 2) & (kJumpCacheSize - 1u)];
        e.folded_va = folded_va;
        e.native    = native;
        e.blk       = blk;
    }

    void Initialize(uint32_t dram_page_base, uint32_t dram_page_count) {
        global.Initialize();
        for (auto& t : per_asid) t.Initialize();
        JumpCacheFlush();
        page_base  = dram_page_base;
        page_count = dram_page_count;
        page_heads.assign(dram_page_count, nullptr);
    }
    void MarkPopulated(uint8_t asid) {
        asid_populated[asid >> 5] |= (1u << (asid & 31u));
    }
    bool ContainsRange(uint32_t start, uint32_t end) const {
        if (global.ContainsRange(start, end)) return true;
        for (uint32_t w = 0; w < 8u; ++w) {
            uint32_t bits = asid_populated[w];
            if (!bits) continue;
            for (uint32_t b = 0; b < 32u; ++b) {
                if ((bits & (1u << b)) &&
                    per_asid[(w << 5) + b].ContainsRange(start, end)) {
                    return true;
                }
            }
        }
        return false;
    }
    /* Drop the removed block's jump-cache slot (QEMU tb_jmp_cache_inval_tb):
       clear only this entry, never the whole cache, so unrelated dispatches
       stay warm across SMC invalidation. */
    static void ClearJcSlot(uint32_t folded_va, void* ctx) {
        auto* sp = static_cast<IsaBlockSpace*>(ctx);
        JumpCacheEntry& e = sp->jump_cache[(folded_va >> 2) & (kJumpCacheSize - 1u)];
        if (e.folded_va == folded_va) {
            e.folded_va = 0;
            e.native    = nullptr;
            e.blk       = nullptr;
        }
    }

    /* QEMU tb_link_page. */
    void IndexInsert(JitBlock* outer, JitBlockIndex* owner, uint32_t index_start,
                     uint32_t index_split = 0,
                     uint32_t index_start2 = kBlockUnindexed) {
        outer->owner        = owner;
        outer->page_next[0] = nullptr;
        outer->page_next[1] = nullptr;
        outer->index_start  = index_start;
        outer->index_split  = index_split;
        outer->index_start2 = index_start2;
        LinkIntoPage(outer, 0, index_start >> 12);
        if (index_split != 0 && (index_start2 >> 12) != (index_start >> 12)) {
            LinkIntoPage(outer, 1, index_start2 >> 12);
        }
    }

    void LinkIntoPage(JitBlock* outer, int slot, uint32_t pg) {
        if (pg >= page_base && pg < page_base + page_count) {
            JitBlock*& head = page_heads[pg - page_base];
            outer->page_next[slot] = head;
            head = outer;
        }
    }

    static int LinkSlot(const JitBlock* blk, uint32_t pg) {
        return (blk->index_start >> 12) == pg ? 0 : 1;
    }

    static bool RangesOverlap(uint32_t a_lo, uint32_t a_hi, uint32_t b_lo,
                              uint32_t b_hi) {
        return a_hi >= b_lo && a_lo <= b_hi;
    }

    /* QEMU tb_invalidate_phys_page_range__locked. */
    static bool IntersectsBlock(const JitBlock* blk, uint32_t lo, uint32_t hi) {
        const uint32_t span = blk->guest_end - blk->guest_start;
        if (blk->index_split == 0) {
            return RangesOverlap(blk->index_start, blk->index_start + span, lo, hi);
        }
        return RangesOverlap(blk->index_start,
                             blk->index_start + blk->index_split - 1u, lo, hi) ||
               RangesOverlap(blk->index_start2,
                             blk->index_start2 + (span - blk->index_split), lo, hi);
    }

    /* QEMU's !cpu_physical_memory_get_dirty_flag(DIRTY_MEMORY_CODE): the CODE bit
       is cleared exactly while a page's first_tb list is non-empty (tb_page_add /
       tb_invalidate_phys_page_range__locked), so the list itself is the predicate. */
    bool PageHasBlocks(uint32_t index_addr) const {
        const uint32_t pg = index_addr >> 12;
        if (pg < page_base || pg >= page_base + page_count) return false;
        return page_heads[pg - page_base] != nullptr;
    }

    void UnlinkFromPage(JitBlock* outer, int slot) {
        if (slot == 1 &&
            (outer->index_split == 0 ||
             (outer->index_start2 >> 12) == (outer->index_start >> 12))) {
            return;
        }
        const uint32_t pg =
            (slot == 0 ? outer->index_start : outer->index_start2) >> 12;
        if (pg < page_base || pg >= page_base + page_count) return;
        JitBlock** pp = &page_heads[pg - page_base];
        while (JitBlock* b = *pp) {
            if (b == outer) { *pp = b->page_next[slot]; return; }
            pp = &b->page_next[LinkSlot(b, pg)];
        }
    }
    void UnlinkPage(JitBlock* outer) {
        UnlinkFromPage(outer, 0);
        UnlinkFromPage(outer, 1);
    }
    /* QEMU tb_invalidate_phys_page_range__locked. */
    uint32_t RemoveRange(uint32_t lo, uint32_t hi) {
        uint32_t removed = 0;
        const uint32_t pg_lo = lo >> 12;
        const uint32_t pg_hi = hi >> 12;
        for (uint32_t pg = pg_lo; pg <= pg_hi; ++pg) {
            if (pg < page_base || pg >= page_base + page_count) continue;
            JitBlock** pp = &page_heads[pg - page_base];
            while (JitBlock* blk = *pp) {
                const int n = LinkSlot(blk, pg);
                if (!IntersectsBlock(blk, lo, hi)) {
                    pp = &blk->page_next[n];
                } else {
                    *pp = blk->page_next[n];
                    UnlinkFromPage(blk, 1 - n);
                    blk->owner->RemoveNode(blk, &ClearJcSlot, this);
                    ++removed;
                }
            }
        }
        return removed;
    }

    void RemoveBlock(JitBlock* outer) {
        UnlinkPage(outer);
        outer->owner->RemoveNode(outer, &ClearJcSlot, this);
    }
    void FlushAll() {
        global.Flush();
        for (uint32_t w = 0; w < 8u; ++w) {
            uint32_t bits = asid_populated[w];
            if (!bits) continue;
            for (uint32_t b = 0; b < 32u; ++b) {
                if (bits & (1u << b)) per_asid[(w << 5) + b].Flush();
            }
            asid_populated[w] = 0;
        }
        JumpCacheFlush();
        for (auto& h : page_heads) h = nullptr;
    }
};
