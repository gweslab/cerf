#include "emit_full_flush_escape.h"

#include "../arm_jit.h"
#include "../x86_emit.h"

uint8_t* EmitFullFlushAndEscape(uint8_t* cursor, ArmJit* jit,
                                int32_t r15_disp, uint32_t pc_resume) {
    using namespace x86;
    EmitXorRegReg(cursor, kEcx, kEcx);
    EmitMovRegImm32(cursor, kEdx, 0xFFFFFFFFu);
    EmitMovBaseDisp32Imm32(cursor, kStateReg, r15_disp, pc_resume);
    EmitJmp32(cursor, jit->FlushTranslationCacheTrampoline());
    return cursor;
}
