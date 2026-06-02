#include <cstdint>

#include "../arm_jit.h"
#include "../arm_neon_scalar_move.h"
#include "../decoded_insn.h"
#include "../place_fns.h"
#include "../x86_emit.h"

static inline uint32_t ExtractLaneIndex(DecodedInsn* d, uint32_t esize) {
    const uint32_t opc1_lsb = d->cp_opc & 1u;
    const uint32_t opc2     = d->cp & 3u;
    if (esize == 8u) {
        return (opc1_lsb << 2) | opc2;
    }
    return (opc1_lsb << 1) | (opc2 >> 1);
}

/* VMOV (ARM core register to scalar) — A8.8.341, L=0. */
uint8_t* EmitNeonCoreToScalar(uint8_t*      cursor,
                              DecodedInsn*  d,
                              BlockContext* ctx) {
    using namespace x86;
    ArmJit* jit = ctx->jit;

    /* Rt == 15 is UNPREDICTABLE per A8.8.341 line 45180. */
    if (d->rd == 15u) {
        return EmitRaiseUndAndReturn(cursor, d, ctx);
    }

    const uint32_t esize      = (d->cp_opc & 2u) ? 8u : 16u;
    const uint32_t lane_index = ExtractLaneIndex(d, esize);
    const uint32_t d_idx      = (((d->cp >> 2) & 1u) << 4) | (d->crn & 0xFu);
    const uint32_t rt_index   = d->rd;

    EmitPush32(cursor, rt_index);
    EmitPush32(cursor, esize);
    EmitPush32(cursor, lane_index);
    EmitPush32(cursor, d_idx);
    EmitPush32(cursor,
        static_cast<uint32_t>(reinterpret_cast<uintptr_t>(jit->NeonScalarMove())));
    EmitCall(cursor, reinterpret_cast<void*>(
        &ArmNeonScalarMove::HandleCoreToScalarHelper));
    EmitAddRegImm32(cursor, kEsp, 20);
    return cursor;
}

/* VMOV (scalar to ARM core register) — A8.8.342, L=1. cp_opc<2> = U
   (0=signed extend, 1=zero extend) for esize=8/16. */
uint8_t* EmitNeonScalarToCore(uint8_t*      cursor,
                              DecodedInsn*  d,
                              BlockContext* ctx) {
    using namespace x86;
    ArmJit* jit = ctx->jit;

    /* Rt == 15 is UNPREDICTABLE per A8.8.342 line 45263. */
    if (d->rd == 15u) {
        return EmitRaiseUndAndReturn(cursor, d, ctx);
    }

    const uint32_t esize        = (d->cp_opc & 2u) ? 8u : 16u;
    const uint32_t lane_index   = ExtractLaneIndex(d, esize);
    const uint32_t n_idx        = (((d->cp >> 2) & 1u) << 4) | (d->crn & 0xFu);
    const uint32_t rt_index     = d->rd;
    const uint32_t unsigned_ext = (d->cp_opc >> 2) & 1u;  /* bit 23 = U */

    EmitPush32(cursor, rt_index);
    EmitPush32(cursor, unsigned_ext);
    EmitPush32(cursor, esize);
    EmitPush32(cursor, lane_index);
    EmitPush32(cursor, n_idx);
    EmitPush32(cursor,
        static_cast<uint32_t>(reinterpret_cast<uintptr_t>(jit->NeonScalarMove())));
    EmitCall(cursor, reinterpret_cast<void*>(
        &ArmNeonScalarMove::HandleScalarToCoreHelper));
    EmitAddRegImm32(cursor, kEsp, 24);
    return cursor;
}
