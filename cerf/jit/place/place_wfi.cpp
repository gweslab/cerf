#include <cstddef>

#include "../arm_jit.h"
#include "../place_fns.h"
#include "../x86_emit.h"

/* ARMv7 WFI hint, encoding A1 (ARM ARM DDI 0406C.c §A8.8.425, page A8-1106).
   Without this place_fn WFI silently NOPs via PlaceMSRImmediate's empty-
   mask branch; the kernel idle loop then re-dispatches at JIT speed
   (~24000 OEMIdle/sec observed) instead of waiting for the next IRQ. */
uint8_t* PlaceWfi(uint8_t* cursor, DecodedInsn* d, BlockContext* ctx) {
    using namespace x86;
    (void)d;
    EmitMovRegImm32(cursor, kEcx,
        static_cast<uint32_t>(reinterpret_cast<uintptr_t>(ctx->jit)));
    EmitCall(cursor, reinterpret_cast<void*>(&ArmJit::WfiHelper));
    return cursor;
}
