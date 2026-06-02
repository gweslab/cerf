#include <cstdint>

#include "../arm_jit.h"
#include "../arm_neon_simd_3same.h"
#include "../decoded_insn.h"
#include "../place_fns.h"
#include "../x86_emit.h"

/* 3-registers-same-length integer/logical data-proc (A7.4.1), e.g. VADD
   (A8.8.282) / VSUB (A8.8.414). Decoder stashes the raw word in
   d->immediate and the op selector (ArmNeonSimd3Same::kS3*) in d->op1.
   Encoding: 1111 001U bit23 D size Vn Vd opc N Q M c Vm. */
uint8_t* PlaceNeonData3Same(uint8_t*      cursor,
                            DecodedInsn*  d,
                            BlockContext* ctx) {
    using namespace x86;
    ArmJit* jit = ctx->jit;

    const uint32_t w     = d->immediate;
    const uint32_t op    = d->op1;
    const uint32_t Vn    = (w >> 16) & 0xFu;
    const uint32_t Vd    = (w >> 12) & 0xFu;
    const uint32_t Vm    =  w        & 0xFu;
    const uint32_t Dbit  = (w >> 22) & 1u;
    const uint32_t Nbit  = (w >> 7)  & 1u;
    const uint32_t Mbit  = (w >> 5)  & 1u;
    const uint32_t Q     = (w >> 6)  & 1u;
    const uint32_t size  = (w >> 20) & 3u;
    const uint32_t d_idx = (Dbit << 4) | Vd;
    const uint32_t n_idx = (Nbit << 4) | Vn;
    const uint32_t m_idx = (Mbit << 4) | Vm;

    /* UNDEFINED: Q (quadword) with any odd register. */
    if (Q && ((d_idx & 1u) || (n_idx & 1u) || (m_idx & 1u))) {
        return EmitRaiseUndAndReturn(cursor, d, ctx);
    }

    /* These element ops have no 64-bit (size==11) form: VMUL (A8.8.350),
       VCEQ/VTST/VCGT/VCGE (A8.8.291/421/295/293), VMAX/VMIN (A8.8.334),
       VHADD/VHSUB (A8.8.319), VRHADD (A8.8.387), VABD (A8.8.278). VADD/VSUB
       (I64) and the bitwise logical ops keep their size==11 encodings. */
    if (size == 3u &&
        (op == ArmNeonSimd3Same::kS3Mul  ||
         op == ArmNeonSimd3Same::kS3Ceq  || op == ArmNeonSimd3Same::kS3Tst  ||
         op == ArmNeonSimd3Same::kS3CgtS || op == ArmNeonSimd3Same::kS3CgtU ||
         op == ArmNeonSimd3Same::kS3CgeS || op == ArmNeonSimd3Same::kS3CgeU ||
         op == ArmNeonSimd3Same::kS3MaxS || op == ArmNeonSimd3Same::kS3MaxU ||
         op == ArmNeonSimd3Same::kS3MinS || op == ArmNeonSimd3Same::kS3MinU ||
         op == ArmNeonSimd3Same::kS3HaddS  || op == ArmNeonSimd3Same::kS3HaddU  ||
         op == ArmNeonSimd3Same::kS3HsubS  || op == ArmNeonSimd3Same::kS3HsubU  ||
         op == ArmNeonSimd3Same::kS3RhaddS || op == ArmNeonSimd3Same::kS3RhaddU ||
         op == ArmNeonSimd3Same::kS3AbdS   || op == ArmNeonSimd3Same::kS3AbdU)) {
        return EmitRaiseUndAndReturn(cursor, d, ctx);
    }

    /* VMUL.P8 (A8.8.350, op=1): polynomial multiply is defined ONLY at
       8-bit elements; size != 00 is UNDEFINED (A8.8.350 line 45826). */
    if (op == ArmNeonSimd3Same::kS3MulP && size != 0u) {
        return EmitRaiseUndAndReturn(cursor, d, ctx);
    }

    const uint32_t esize = 8u << size;
    const uint32_t regs  = Q ? 2u : 1u;

    /* __cdecl PUSH RTL: regs, esize, m_idx, n_idx, d_idx, op, svc_ptr.
       Handler is void (these ops cannot fault), so just continue after. */
    EmitPush32(cursor, regs);
    EmitPush32(cursor, esize);
    EmitPush32(cursor, m_idx);
    EmitPush32(cursor, n_idx);
    EmitPush32(cursor, d_idx);
    EmitPush32(cursor, op);
    EmitPush32(cursor,
        static_cast<uint32_t>(reinterpret_cast<uintptr_t>(jit->Simd3Same())));
    EmitCall(cursor, reinterpret_cast<void*>(&ArmNeonSimd3Same::HandleSimd3SameHelper));
    EmitAddRegImm32(cursor, kEsp, 28);
    return cursor;
}
