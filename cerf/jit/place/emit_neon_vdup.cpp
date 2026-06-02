#include <cstdint>

#include "../arm_jit.h"
#include "../arm_neon.h"
#include "../decoded_insn.h"
#include "../place_fns.h"
#include "../x86_emit.h"

/* VDUP (ARM core register), DDI0406C A8.8.314, decoded as a cp11
   register transfer (Table A7-22): cp_opc = 1:B:Q, cp = D:0:E,
   crn = Vd, rd = Rt. */
uint8_t* EmitNeonVdup(uint8_t*      cursor,
                      DecodedInsn*  d,
                      BlockContext* ctx) {
    using namespace x86;
    ArmJit* jit = ctx->jit;

    const uint32_t Q     =  d->cp_opc       & 1u;
    const uint32_t B     = (d->cp_opc >> 1) & 1u;
    const uint32_t E     =  d->cp           & 1u;
    const uint32_t d_bit = (d->cp     >> 2) & 1u;
    const uint32_t d_idx = (d_bit << 4) | d->crn;
    const uint32_t rt    =  d->rd;
    const uint32_t regs  = Q ? 2u : 1u;
    const uint32_t be    = (B << 1) | E;
    const uint32_t esize = (be == 0u) ? 32u : (be == 1u) ? 16u
                         : (be == 2u) ? 8u : 0u;

    /* __cdecl PUSH RTL: regs, esize, rt, d_idx, pc, neon_ptr. */
    EmitPush32(cursor, regs);
    EmitPush32(cursor, esize);
    EmitPush32(cursor, rt);
    EmitPush32(cursor, d_idx);
    EmitPush32(cursor, d->guest_address);
    EmitPush32(cursor,
        static_cast<uint32_t>(reinterpret_cast<uintptr_t>(jit->Neon())));
    EmitCall(cursor, reinterpret_cast<void*>(&ArmNeon::HandleVdupHelper));
    EmitAddRegImm32(cursor, kEsp, 24);
    EmitTestRegReg(cursor, kEax, kEax);
    uint8_t* continue_label = EmitJzLabel(cursor);
    EmitRetn(cursor, 0);
    FixupLabel(continue_label, cursor);
    return cursor;
}
