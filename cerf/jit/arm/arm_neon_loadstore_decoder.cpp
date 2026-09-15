#include "arm_neon_loadstore_decoder.h"

#include "../../core/cerf_emulator.h"
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
        /* ARM DDI 0406C.c Table A7-20 (p. A7-275) and Table A7-21
           (p. A7-276): with A = 0 both allocate B = 000x, 0010, 0011, 010x,
           011x, 100x and 1010 only. A7.7 (p. A7-275): "Other encodings in this
           space are UNDEFINED." */
        if (!fn) {
            insn->cond      = 14;
            insn->immediate = op.word;
            insn->place_fn  = &EmitRaiseUndAndReturn;
            return true;
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
    /* ARM DDI 0406C.c Table A7-21 (p. A7-276): with A = 1, B = 1100, 1101,
       1110 and 1111 are the VLD1/2/3/4 single-structure-to-all-lanes loads.
       Table A7-20 (p. A7-275) allocates no B = 11xx store, and A7.7
       (p. A7-275): "Other encodings in this space are UNDEFINED." */
    insn->cond      = 14;
    insn->immediate = op.word;
    insn->place_fn = op.neon_load_store_single.l == 0u ? &EmitRaiseUndAndReturn
        : &PlaceNeonLoadAllLanes;
    return true;
}
