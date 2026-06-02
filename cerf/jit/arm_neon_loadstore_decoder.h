#pragma once

#include "../core/service.h"

struct DecodedInsn;
union  ArmOpcode;

/* Decoder for the marker==0x4 cond==15 NEON encoding region: load/store
   (A7.7). VLD1/VST1, VLD2/3/4 + VST2/3/4 interleaved, single-lane,
   single-element-to-all-lanes. Caller has already gated on the marker. */
class ArmNeonLoadStoreDecoder : public Service {
public:
    using Service::Service;

    bool Decode(DecodedInsn* insn, ArmOpcode op);
};
