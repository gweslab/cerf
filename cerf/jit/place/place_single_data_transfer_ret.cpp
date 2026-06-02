#include "../../core/log.h"
#include "../place_fns.h"
#include "../x86_emit.h"

uint8_t* PlaceSingleDataTransferRET(uint8_t*      cursor,
                                    DecodedInsn*  d,
                                    BlockContext* ctx) {
    using namespace x86;

    if (!d->r15_modified) {
        LOG(Caution,
            "PlaceSingleDataTransferRET: r15_modified must be set on the "
            "RET-idiom LDR; got 0 at guest pc=0x%08X\n", d->guest_address);
        CerfFatalExit(CERF_FATAL_RUNTIME_ERROR);
    }

    d->r15_modified = 0;
    cursor = PlaceSingleDataTransfer(cursor, d, ctx);
    d->r15_modified = 1;

    EmitJmp32(cursor, ctx->pop_shadow_stack_helper_target);
    return cursor;
}
