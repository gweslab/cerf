#include <cstdint>

#include "../arm_jit.h"
#include "../place_fns.h"
#include "../x86_emit.h"
#include "../../core/log.h"

/* Loud stub for an architecturally-VALID coproc instruction not yet
   implemented — NOT for EmitRaiseUndAndReturn's cases (genuine UND / data
   decoded past a block end). Routing a real-but-unimplemented coproc to UND
   hangs the guest silently; fires at RUNTIME so speculative compiles don't trip. */

namespace {

[[noreturn]] void CoprocUnimplementedFatalHelper(uint32_t pc, uint32_t cp_info) {
    LOG(Jit, "FATAL: unimplemented (but architecturally valid) coprocessor "
             "instruction executed at guest pc=0x%08X — p%u CRn=c%u CRm=c%u "
             "opc1=%u opc2=%u %s. Implement it in the SoC CoprocEmitter; do NOT "
             "leave it on the UND path.\n",
        pc, (cp_info >> 24) & 0xFu, (cp_info >> 16) & 0xFu,
        (cp_info >> 8) & 0xFu, (cp_info >> 4) & 0xFu, (cp_info >> 1) & 0x7u,
        (cp_info & 1u) ? "MRC/read" : "MCR/write");
    CerfFatalExit(CERF_FATAL_RUNTIME_ERROR);
}

}  // namespace

uint8_t* EmitCoprocUnimplementedFatal(uint8_t* cursor, DecodedInsn* d, BlockContext* ctx) {
    using namespace x86;
    (void)ctx;
    const uint32_t cp_info = (d->cp_num << 24) | (d->crn << 16) | (d->crm << 8) |
                             (d->cp_opc << 4) | (d->cp << 1) | (d->l ? 1u : 0u);
    EmitPush32(cursor, cp_info);
    EmitPush32(cursor, d->guest_address);
    EmitCall(cursor, reinterpret_cast<void*>(&CoprocUnimplementedFatalHelper));
    EmitAddRegImm32(cursor, kEsp, 8);
    EmitRetn(cursor, 0);
    return cursor;
}
