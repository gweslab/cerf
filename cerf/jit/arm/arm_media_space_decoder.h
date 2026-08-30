#pragma once

#include "../../core/service.h"

class ArmProcessorConfig;
struct DecodedInsn;
union  ArmOpcode;

/* Decoder for the Table A5-16 media space (ARM DDI 0406C.c, p. A5-209). */
class ArmMediaSpaceDecoder : public Service {
public:
    using Service::Service;

    bool ShouldRegister() override;
    void OnReady() override;

    bool Decode(DecodedInsn* insn, ArmOpcode op);

private:
    bool DecodeBitfield(DecodedInsn* insn, ArmOpcode op);
    bool DecodePackSatReverse(DecodedInsn* insn, ArmOpcode op);
    bool DecodeSignedSaturate(DecodedInsn* insn, ArmOpcode op);
    bool DecodeDualMultiply(DecodedInsn* insn, ArmOpcode op, bool is_long);
    bool DecodeMostSignificantMultiply(DecodedInsn* insn, ArmOpcode op);

    ArmProcessorConfig* processor_config_ = nullptr;
};
