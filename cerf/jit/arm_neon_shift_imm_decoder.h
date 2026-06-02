#pragma once

#include "../core/service.h"

struct DecodedInsn;
union  ArmOpcode;

/* Decoder for the bit23==1 sub-region of the cond==15 NEON data-processing
   encoding: 2-reg-shift-immediate (A7.4.4) and 1-reg-modified-immediate
   (A7.4.6 — the L:imm6 == 0000xxx carve-out). */
class ArmNeonShiftImmDecoder : public Service {
public:
    using Service::Service;

    /* Caller guarantees bit23==1 && c==1 && marker==0x1. Returns true on a
       matched encoding (or a recognized-but-halted variant); false if the
       encoding doesn't match any recognized op in this region. */
    bool Decode(DecodedInsn* insn, ArmOpcode op);
};
