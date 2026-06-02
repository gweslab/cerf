#include "coproc_emitter.h"

#include "place_fns.h"

uint8_t* CoprocEmitter::EmitRegisterTransferDouble(uint8_t*      cursor,
                                                   DecodedInsn*  d,
                                                   BlockContext* ctx) {
    return EmitRaiseUndAndReturn(cursor, d, ctx);
}
