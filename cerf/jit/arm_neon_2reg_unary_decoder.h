#pragma once

#include "../core/service.h"

struct DecodedInsn;
union  ArmOpcode;

/* Decoder for the bit23==1 && c==0 && bits[21:20]==11 sub-region of the
   cond==15 NEON data-processing encoding: A7.4.5 "Two registers,
   miscellaneous". Caller guarantees the gating bits. */
class ArmNeon2RegUnaryDecoder : public Service {
public:
    using Service::Service;

    bool Decode(DecodedInsn* insn, ArmOpcode op);
};
