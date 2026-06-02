#include <cstddef>

#include "../arm_jit.h"
#include "../cpu_state.h"
#include "../place_fns.h"
#include "../x86_emit.h"

uint8_t* PlaceBxImpl(uint8_t*      cursor,
                     DecodedInsn*  d,
                     BlockContext* ctx,
                     bool          is_call) {
    using namespace x86;

    /* MOV EAX, [ESI + GPRs[Rd]] */
    EmitMovRegBaseDisp32(cursor, kEax, kStateReg,
        static_cast<int32_t>(offsetof(ArmCpuState, gprs) + d->rd * 4));

    cursor = EmitArmInterworkingMaskEax(cursor);

    /* MOV [ESI + GPRs[15]], EAX */
    EmitMovBaseDisp32Reg(cursor, kStateReg,
        static_cast<int32_t>(offsetof(ArmCpuState, gprs) + 15 * 4),
        kEax);

    if (is_call || d->rd == ArmGpr::kR15 || d->rd == 12) {
        cursor = PlaceR15ModifiedHelper(cursor, d, ctx);
    } else {
        /* BX LR or similar return — try the shadow-stack pop. */
        EmitJmp32(cursor, ctx->pop_shadow_stack_helper_target);
    }

    return cursor;
}
