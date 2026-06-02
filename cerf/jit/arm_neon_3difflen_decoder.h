#pragma once

#include "../core/service.h"

struct DecodedInsn;
union  ArmOpcode;

/* Decoder for the bit23==1 && c==0 sub-region of the cond==15 NEON
   data-processing encoding: 3-registers-of-different-lengths (A7.4.2).
   Caller guarantees marker==0x1 and the bit23/c gating. */
class ArmNeon3DiffLenDecoder : public Service {
public:
    using Service::Service;

    bool Decode(DecodedInsn* insn, ArmOpcode op);
};
