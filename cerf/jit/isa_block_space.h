#pragma once

#include <cstdint>
#include <cstring>
#include <vector>

#include "jit_block_index.h"

/* VA-indexed jump cache (QEMU tb_jmp_cache). Keyed by FCSE-folded VA; the
   block index itself is phys-keyed. Flushed on context switch / SMC / full
   flush so a stale VA→native mapping never survives an address-space change. */
constexpr uint32_t kJumpCacheSize = 4096;   /* power of two */
struct JumpCacheEntry {
    uint32_t folded_va;
    void*    native;
};

/* Per-ISA blocks. CE7 sets FCSE process_id=0, so the index key no
   longer separates address spaces — partition by ASID: global (nG=0
   kernel/shared) shared across processes; user (nG=1) in per_asid. */
struct IsaBlockSpace {
    JitBlockIndex global;
    JitBlockIndex per_asid[256];
    uint32_t      asid_populated[8] = {0};   /* bit i ⇒ per_asid[i] non-empty */
    JumpCacheEntry jump_cache[kJumpCacheSize];

    /* Per-physical-page intrusive list of outer blocks (QEMU
       PageDesc.first_tb), sized over the DRAM page extent. SMC RemoveRange
       walks one page's list instead of scanning the whole VA-ordered tree. */
    std::vector<JitBlock*> page_heads;
    uint32_t               page_base  = 0;   /* first DRAM page number */
    uint32_t               page_count = 0;

    void JumpCacheFlush() { std::memset(jump_cache, 0, sizeof(jump_cache)); }

    void* JumpCacheLookup(uint32_t folded_va) const {
        const JumpCacheEntry& e = jump_cache[(folded_va >> 2) & (kJumpCacheSize - 1u)];
        return e.folded_va == folded_va ? e.native : nullptr;
    }

    void JumpCacheInsert(uint32_t folded_va, void* native) {
        JumpCacheEntry& e = jump_cache[(folded_va >> 2) & (kJumpCacheSize - 1u)];
        e.folded_va = folded_va;
        e.native    = native;
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
        }
    }

    /* Link an outer block into its physical page's list (DRAM-resident only;
       flash/ROM code is never SMC-dirtied so needs no entry). */
    void IndexInsert(JitBlock* outer, JitBlockIndex* owner) {
        outer->owner     = owner;
        outer->page_next = nullptr;
        const uint32_t pg = outer->phys_start >> 12;
        if (pg >= page_base && pg < page_base + page_count) {
            JitBlock*& head = page_heads[pg - page_base];
            outer->page_next = head;
            head = outer;
        }
    }

    void UnlinkPage(JitBlock* outer) {
        const uint32_t pg = outer->phys_start >> 12;
        if (pg < page_base || pg >= page_base + page_count) return;
        JitBlock** pp = &page_heads[pg - page_base];
        while (*pp) {
            if (*pp == outer) { *pp = outer->page_next; return; }
            pp = &(*pp)->page_next;
        }
    }
    /* SMC: remove every block on physical pages [phys_lo, phys_hi] via the
       page list — RemoveNode RbDeletes each from its owning tree + clears its
       jump-cache slot. O(blocks-on-page), not a whole-tree scan. */
    uint32_t RemoveRange(uint32_t phys_lo, uint32_t phys_hi) {
        uint32_t removed = 0;
        const uint32_t pg_lo = phys_lo >> 12;
        const uint32_t pg_hi = phys_hi >> 12;
        for (uint32_t pg = pg_lo; pg <= pg_hi; ++pg) {
            if (pg < page_base || pg >= page_base + page_count) continue;
            JitBlock* blk = page_heads[pg - page_base];
            page_heads[pg - page_base] = nullptr;
            while (blk) {
                JitBlock* next = blk->page_next;
                blk->owner->RemoveNode(blk, &ClearJcSlot, this);
                ++removed;
                blk = next;
            }
        }
        return removed;
    }

    /* Evict the single outer block whose folded-VA range contains folded_va
       (FCSE-PID-reuse stale dedup): unlink from its page list, then RbDelete. */
    uint32_t RemoveExact(uint32_t folded_va) {
        JitBlock*      outer = global.FindOuter(folded_va);
        JitBlockIndex* owner = &global;
        for (uint32_t w = 0; w < 8u && !outer; ++w) {
            uint32_t bits = asid_populated[w];
            for (uint32_t bit = 0; bit < 32u && !outer; ++bit) {
                if (bits & (1u << bit)) {
                    outer = per_asid[(w << 5) + bit].FindOuter(folded_va);
                    if (outer) owner = &per_asid[(w << 5) + bit];
                }
            }
        }
        if (!outer) return 0;
        UnlinkPage(outer);
        owner->RemoveNode(outer, &ClearJcSlot, this);
        return 1;
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
