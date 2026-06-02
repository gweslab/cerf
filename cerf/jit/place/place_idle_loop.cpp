#include "../arm_jit.h"
#include "../place_fns.h"
#include "../x86_emit.h"

uint8_t* PlaceIdleLoop(uint8_t*      cursor,
                       DecodedInsn*  d,
                       BlockContext* ctx) {
    using namespace x86;

    /* DO NOT replace WfiHelper with a raw WaitForSingleObject(INFINITE):
       WfiHelper advances guest_cycle_counter by elapsed wall-clock, an
       infinite wait does not — frozen cycles freeze the icount OSCR, the
       OS-timer match the guest idles on is never reached, and no tick IRQ
       ever fires to wake it (permanent park). */
    EmitMovRegImm32(cursor, kEcx,
        static_cast<uint32_t>(reinterpret_cast<uintptr_t>(ctx->jit)));
    EmitCall(cursor, reinterpret_cast<void*>(&ArmJit::WfiHelper));
    return PlaceBranch(cursor, d, ctx);
}
