#pragma once

#include <cstdint>

class ArmJit;

/* Emits a whole-cache flush + escape to the dispatcher resuming at
   pc_resume. Shared by the whole-I-cache invalidate and TTBR0 switch. */
uint8_t* EmitFullFlushAndEscape(uint8_t* cursor, ArmJit* jit,
                                int32_t r15_disp, uint32_t pc_resume);
