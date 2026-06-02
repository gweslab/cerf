#pragma once

#include "../core/service.h"

struct DecodedInsn;
union  ArmOpcode;

/* Decoder for A7.4.1 (3-reg same length). Caller gates on bit23==0. */
class ArmNeon3RegSameDecoder : public Service {
public:
    using Service::Service;

    bool Decode(DecodedInsn* insn, ArmOpcode op);
};
