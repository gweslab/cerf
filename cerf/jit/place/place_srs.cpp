#include <cstddef>

#include "../arm_jit.h"
#include "../cpu_state.h"
#include "../place_fns.h"
#include "../x86_emit.h"

uint8_t* PlaceSrs(uint8_t* cursor, DecodedInsn* d, BlockContext* ctx) {
    using namespace x86;

    /* MOV ECX, <encoded> — pack P/U/W/target_mode into __fastcall arg 1:
       bit 7 = P, bit 6 = U, bit 5 = W, bits 4:0 = target_mode. */
    const uint32_t encoded =
        (static_cast<uint32_t>(d->p)         << 7) |
        (static_cast<uint32_t>(d->u)         << 6) |
        (static_cast<uint32_t>(d->w)         << 5) |
        (static_cast<uint32_t>(d->immediate) & 0x1Fu);
    EmitMovRegImm32(cursor, kEcx, encoded);

    /* MOV EDX, jit (__fastcall arg 2). */
    EmitMovRegImm32(cursor, kEdx,
        static_cast<uint32_t>(reinterpret_cast<uintptr_t>(ctx->jit)));

    /* PUSH guest_pc (__fastcall arg 3 on stack — for diagnostics). */
    EmitPush32(cursor, d->guest_address);

    /* CALL SrsHelper. __fastcall callee-cleans the stack arg. */
    EmitCall(cursor, reinterpret_cast<void*>(&ArmJit::SrsHelper));

    /* SRS does not write PC — execution falls through to the next
       instruction. No dispatch. */
    return cursor;
}
