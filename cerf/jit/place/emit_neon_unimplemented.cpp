#include <cstdint>

#include "../../core/log.h"
#include "../decoded_insn.h"
#include "../place_fns.h"

/* A NEON encoding CERF recognizes but does not yet emulate: halt with
   encoding + PC instead of a silent guest UND (which would surface as an
   unattributable illegal-instruction fault, weeks to diagnose). The
   decoder stashes the raw opcode word in d->immediate. */
uint8_t* PlaceNeonUnimplemented(uint8_t*      /*cursor*/,
                                DecodedInsn*  d,
                                BlockContext* /*ctx*/) {
    LOG(Caution,
        "PlaceNeonUnimplemented: unimplemented NEON instruction "
        "encoding=0x%08X at pc=0x%08X\n",
        d->immediate, d->guest_address);
    CerfFatalExit(CERF_FATAL_RUNTIME_ERROR);
}
