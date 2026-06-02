#include <cstdint>

#include "../arm_jit.h"
#include "../arm_neon.h"
#include "../decoded_insn.h"
#include "../place_fns.h"
#include "../x86_emit.h"

/* VLD1/2/3/4 + VST1/2/3/4 (single element to one lane), DDI0406C
   A8.8.321/324/327/330 (load), A8.8.405/407/409/411 (store). Decoder
   packs: rn=Rn, rm=Rm, crn=Vd, n=D, l=L, cp=size, op1=N-1,
   crm=index_align[3:0]. */
uint8_t* PlaceNeonLoadStoreSingleLane(uint8_t*      cursor,
                                      DecodedInsn*  d,
                                      BlockContext* ctx) {
    using namespace x86;
    ArmJit* jit = ctx->jit;

    const uint32_t size = d->cp;          /* 0..2 (size==3 -> all-lanes path) */
    const uint32_t N    = d->op1 + 1u;    /* 1..4 */
    const uint32_t ia   = d->crm;         /* index_align[3:0] */

    /* index (lane) + register spacing inc, per size (case-size blocks). */
    uint32_t index, inc = 1u;
    if (size == 0u) {
        index = ia >> 1;                                  /* ia[3:1] */
    } else if (size == 1u) {
        index = ia >> 2;          inc = (ia & 2u) ? 2u : 1u;  /* ia[3:2], ia[1] */
    } else {
        index = ia >> 3;          inc = (ia & 4u) ? 2u : 1u;  /* ia[3],  ia[2] */
    }

    /* Per-(N,size) UNDEFINED + alignment (A8.8.321/324/327/330). */
    const uint32_t ia0  = ia & 1u;
    const uint32_t ia10 = ia & 3u;
    bool     undef     = false;
    uint32_t alignment = 1u;
    switch (N) {
        case 1u:
            if (size == 0u)      { undef = (ia0 != 0u); }
            else if (size == 1u) { undef = ((ia & 2u) != 0u); alignment = ia0 ? 2u : 1u; }
            else                 { undef = ((ia & 4u) != 0u) || (ia10 != 0u && ia10 != 3u);
                                   alignment = (ia10 == 0u) ? 1u : 4u; }
            break;
        case 2u:
            if (size == 0u)      { alignment = ia0 ? 2u : 1u; }
            else if (size == 1u) { alignment = ia0 ? 4u : 1u; }
            else                 { undef = ((ia & 2u) != 0u); alignment = ia0 ? 8u : 1u; }
            break;
        case 3u:
            if (size == 2u)      { undef = (ia10 != 0u); }
            else                 { undef = (ia0 != 0u); }
            break;  /* alignment always 1 */
        default:  /* N == 4 */
            if (size == 0u)      { alignment = ia0 ? 4u : 1u; }
            else if (size == 1u) { alignment = ia0 ? 8u : 1u; }
            else                 { undef = (ia10 == 3u);
                                   alignment = (ia10 == 0u) ? 1u : (4u << ia10); }
            break;
    }
    if (undef) {
        return EmitRaiseUndAndReturn(cursor, d, ctx);
    }

    const uint32_t d_idx = (d->n << 4) | d->crn;
    uint32_t align_log2 = 0u;
    while ((1u << align_log2) < alignment) ++align_log2;
    const uint32_t flags = (d->l & 1u)
                         | ((N - 1u)     << 1)
                         | ((inc - 1u)   << 3)
                         | (size         << 4)
                         | (index        << 6)
                         | (align_log2   << 9);

    /* __cdecl PUSH RTL: flags, rm, rn, d_idx, pc, neon_ptr. */
    EmitPush32(cursor, flags);
    EmitPush32(cursor, d->rm);
    EmitPush32(cursor, d->rn);
    EmitPush32(cursor, d_idx);
    EmitPush32(cursor, d->guest_address);
    EmitPush32(cursor,
        static_cast<uint32_t>(reinterpret_cast<uintptr_t>(jit->Neon())));
    EmitCall(cursor, reinterpret_cast<void*>(
        &ArmNeon::HandleLoadStoreSingleLaneHelper));
    EmitAddRegImm32(cursor, kEsp, 24);
    EmitTestRegReg(cursor, kEax, kEax);
    uint8_t* continue_label = EmitJzLabel(cursor);
    EmitRetn(cursor, 0);
    FixupLabel(continue_label, cursor);
    return cursor;
}
