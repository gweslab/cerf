#include <cstdint>

#include "../arm_jit.h"
#include "../../cpu/arm_processor_config.h"
#include "../decoded_insn.h"
#include "../place_fns.h"

uint8_t* EmitVfpRegisterTransfer(uint8_t*      cursor,
                                 DecodedInsn*  d,
                                 BlockContext* ctx) {
    /* VDUP (ARM core register) — NEON, A7-22 (C=1, L=0, A=1xx, B=0x).
       MUST precede the VMRS check: VDUP.8 Qd encodes cp_opc=7, cp=0 and
       would otherwise alias VMRS. HasNeon() gate => non-NEON SoCs fall
       through and UND it, like real hardware. */
    if (ctx->jit->ProcessorConfig()->HasNeon() &&
        d->cp_num == 11 && d->l == 0 &&
        (d->cp_opc & 4u) && (d->cp & 2u) == 0u) {
        return EmitNeonVdup(cursor, d, ctx);
    }

    /* VMOV (ARM core register ↔ scalar) — A8.8.341 / A8.8.342, esize=8
       or 16. MUST precede VMRS: VMOV.U8 Rt, Dn[7] aliases cp_opc=7
       cp=0. esize=32 collapses to VMOV Sn↔Rt (handled below) and is
       not matched here. */
    if (ctx->jit->ProcessorConfig()->HasNeon() && d->cp_num == 11) {
        const bool esize_8  = (d->cp_opc & 2u) != 0u;
        const bool esize_16 = ((d->cp_opc & 2u) == 0u) && ((d->cp & 1u) != 0u);
        if (esize_8 || esize_16) {
            if (d->l == 0u) return EmitNeonCoreToScalar(cursor, d, ctx);
            return EmitNeonScalarToCore(cursor, d, ctx);
        }
    }

    /* VMRS / VMSR — VFP system register R/W (cp_opc=7, CRm=0, op2=0). */
    if (d->cp_opc == 7 && d->crm == 0 && d->cp == 0) {
        return EmitVfpSystemRegTransfer(cursor, d, ctx);
    }

    /* FMRDL/FMRDH: esize-32 scalar VMOV Rt<->Dn[x], cp11 (QEMU vfp.decode
       VMOV_to_gp size=2): Dn=(D<<4)|Vn (D=cp bit2), index=bit21=cp_opc&1,
       lane Sx=(Dn<<1)|index. MUST precede the cp10 rule — FMRDL (cp11,
       cp_opc=0) would else route there and decode the wrong fields. */
    if (d->cp_num == 11 && (d->cp_opc & 6u) == 0u && d->crm == 0 &&
        (d->cp & 3u) == 0u) {
        const uint32_t dn = (((d->cp >> 2) & 1u) << 4) | (d->crn & 0xFu);
        const uint32_t sx = (dn << 1) | (d->cp_opc & 1u);
        return EmitVfpSingleMoveIdx(cursor, d, ctx, sx);
    }

    /* VMOV Sn <-> Rt — cp10 single-register transfer (cp_opc=0, CRm=0,
       op2 low bits = 0; cp bit 2 = Sn extension). */
    if (d->cp_opc == 0 && d->crm == 0 && (d->cp & 3u) == 0u) {
        return EmitVfpSingleMove(cursor, d, ctx);
    }

    return EmitRaiseUndAndReturn(cursor, d, ctx);
}
