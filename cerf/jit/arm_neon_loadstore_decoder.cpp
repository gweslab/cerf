#include "arm_neon_loadstore_decoder.h"

#include "../core/cerf_emulator.h"
#include "arm_opcode.h"
#include "decoded_insn.h"
#include "place_fns.h"

REGISTER_SERVICE(ArmNeonLoadStoreDecoder);

bool ArmNeonLoadStoreDecoder::Decode(DecodedInsn* insn, ArmOpcode op) {
    if (op.neon_load_store.a == 0u) {
        /* Multiple-structure forms (A7-20/A7-21). VLD1/VST1:
           {0010,0110,0111,1010}; VLD2/3/4 + VST2/3/4 (de-interleaved):
           {0011,1000,1001}/{0100,0101}/{0000,0001}. */
        const uint32_t type = op.neon_load_store.type;
        ArmPlaceFn fn = nullptr;
        if (type == 0x2u || type == 0x6u || type == 0x7u || type == 0xAu) {
            fn = &PlaceNeonLoadStoreMultiple;
        } else if (type == 0x0u || type == 0x1u || type == 0x3u ||
                   type == 0x4u || type == 0x5u || type == 0x8u ||
                   type == 0x9u) {
            fn = &PlaceNeonLoadStoreInterleaved;
        }
        if (!fn) {
            return false;
        }
        insn->place_fn = fn;
        insn->cond     = 14;
        insn->rn       = op.neon_load_store.rn;
        insn->rm       = op.neon_load_store.rm;
        insn->crn      = op.neon_load_store.vd;
        insn->n        = op.neon_load_store.d;
        insn->l        = op.neon_load_store.l;
        insn->op1      = type;
        insn->cp       = op.neon_load_store.size;
        insn->crm      = op.neon_load_store.align;
        return true;
    }
    /* A==1: single element to one lane. */
    if (op.neon_load_store_single.size != 3u) {
        insn->place_fn = &PlaceNeonLoadStoreSingleLane;
        insn->cond     = 14;
        insn->rn       = op.neon_load_store_single.rn;
        insn->rm       = op.neon_load_store_single.rm;
        insn->crn      = op.neon_load_store_single.vd;
        insn->n        = op.neon_load_store_single.d;
        insn->l        = op.neon_load_store_single.l;
        insn->cp       = op.neon_load_store_single.size;
        insn->op1      = op.neon_load_store_single.n_minus1;
        insn->crm      = op.neon_load_store_single.index_align;
        return true;
    }
    /* size==11: single-element-to-all-lanes (VLD only) — recognized but
       not yet implemented. Halt loudly rather than silent UND. */
    insn->cond      = 14;
    insn->immediate = op.word;
    insn->place_fn  = &PlaceNeonUnimplemented;
    return true;
}
