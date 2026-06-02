#include <cstddef>

#include "../cpu_state.h"
#include "../place_fns.h"
#include "../x86_emit.h"

uint8_t* PlaceBlxReg(uint8_t*      cursor,
                     DecodedInsn*  d,
                     BlockContext* ctx) {
    using namespace x86;

    /* MOV [ESI + GPRs[R14]], guest_address + 4 */
    EmitMovBaseDisp32Imm32(cursor, kStateReg,
        static_cast<int32_t>(offsetof(ArmCpuState, gprs) + ArmGpr::kR14 * 4u),
        d->guest_address + 4u);

    return PlaceBxImpl(cursor, d, ctx, /*is_call=*/true);
}
