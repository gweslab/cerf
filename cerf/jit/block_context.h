#pragma once

#include <cstdint>

#include "decoded_insn.h"

class ArmJit;

constexpr uint32_t kMaxInsnPerBlock = 100;

struct BlockContext {
    ArmJit* jit;

    DecodedInsn insns[kMaxInsnPerBlock];
    uint32_t    num_insns;

    /* Physical page base (PA & ~0xFFF) of insn[0], from its fetch. Every
       entrypoint's phys_start derives from this: page_base | (folded_va &
       0xFFF) — blocks are 4 KB-page-bounded so all insns share one phys page. */
    uint32_t    block_phys_page_base;

    uint8_t* big_skips1[kMaxInsnPerBlock];
    uint8_t* big_skips2[kMaxInsnPerBlock];
    uint32_t big_skip_count;

    bool     pc_cache_valid;
    uint32_t pc_cache_guest_va;

    uint8_t* interrupt_check_target;

    uint8_t* r15_modified_helper_target;

    uint8_t* branch_helper_target;

    uint8_t* cross_page_branch_helper_target;

    uint8_t* shadow_stack_helper_target;

    uint8_t* pop_shadow_stack_helper_target;

    uint8_t* raise_abort_data_helper_target;

    uint8_t* block_usermode_helper_target;

    uint8_t* sctlr_write_target;
};
