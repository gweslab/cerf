#pragma once

#include <cstdint>

class JitBlockIndex;

struct JitBlock {
    uint32_t   guest_start;   /* FCSE-folded VA — RB index key + jump-cache key */
    uint32_t   guest_end;     /* folded VA, inclusive last byte */
    void*      native_start;
    void*      native_end;
    uint32_t   flags_needed;
    JitBlock*  sub_block;
    uint32_t   phys_start;    /* fetch PA of start — dual-key phys validation + SMC match */

    /* Outer blocks only: intrusive list of every block on one physical
       page (QEMU PageDesc.first_tb) so SMC removal is O(blocks-on-page),
       not a whole-tree scan. owner = the RB tree to RbDelete from. */
    JitBlock*       page_next;
    JitBlockIndex*  owner;
};
