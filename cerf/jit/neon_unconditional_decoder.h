#pragma once

#include "../core/service.h"

class ArmNeon2RegUnaryDecoder;
class ArmNeon2RegScalarDecoder;
class ArmNeon3DiffLenDecoder;
class ArmNeon3RegSameDecoder;
class ArmNeonLoadStoreDecoder;
class ArmNeonShiftImmDecoder;
struct DecodedInsn;
union  ArmOpcode;

/* Top-level dispatcher for cond==15 NEON encodings. Picks the right
   region-specific sub-decoder; carries no decode logic itself. */
class NeonUnconditionalDecoder : public Service {
public:
    using Service::Service;

    void OnReady() override;

    bool DecodeLoadStore(DecodedInsn* insn, ArmOpcode op);
    bool DecodeData3reg(DecodedInsn* insn, ArmOpcode op);

private:
    ArmNeonLoadStoreDecoder*   loadstore_decoder_      = nullptr;
    ArmNeon3RegSameDecoder*    three_regsame_decoder_  = nullptr;
    ArmNeonShiftImmDecoder*    shift_imm_decoder_      = nullptr;
    ArmNeon3DiffLenDecoder*    three_difflen_decoder_  = nullptr;
    ArmNeon2RegScalarDecoder*  two_regscalar_decoder_  = nullptr;
    ArmNeon2RegUnaryDecoder*   two_reg_unary_decoder_  = nullptr;
};
