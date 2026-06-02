#pragma once

#include <cstdint>

#include "../core/service.h"

class ArmCpu;
class ArmProcessorConfig;
class NeonUnconditionalDecoder;
struct DecodedInsn;
union  ArmOpcode;
union  ThumbOpcode;

class ArmDecoder : public Service {
public:
    using Service::Service;

    void OnReady() override;

    /* ARM-mode 32-bit instruction decode. Returns false on UNDEFINED
       (caller stops decoding the block). */
    bool DecodeArm(DecodedInsn* insn, uint32_t opcode_word);

    /* Thumb-mode 16-bit instruction decode. Same return contract. */
    bool DecodeThumb(DecodedInsn* insn, uint16_t opcode_word);

private:
    void DecodeThumbMoveAddSub             (DecodedInsn* d, ThumbOpcode op);
    void DecodeThumbMathImmediate          (DecodedInsn* d, ThumbOpcode op);
    void DecodeThumbALUOperation           (DecodedInsn* d, ThumbOpcode op);
    void DecodeThumbHiOps                  (DecodedInsn* d, ThumbOpcode op);
    void DecodeThumbPCRelativeLoad         (DecodedInsn* d, ThumbOpcode op);
    void DecodeThumbLoadStoreRegisterOffset(DecodedInsn* d, ThumbOpcode op);
    void DecodeThumbLoadStoreByteHalfWord  (DecodedInsn* d, ThumbOpcode op);
    void DecodeThumbCase2                  (DecodedInsn* d, ThumbOpcode op);
    void DecodeThumbLoadStoreImmediateOffset(DecodedInsn* d, ThumbOpcode op);
    void DecodeThumbLoadStoreHalfWord      (DecodedInsn* d, ThumbOpcode op);
    void DecodeThumbLoadStoreSPRelative    (DecodedInsn* d, ThumbOpcode op);
    void DecodeThumbLoadAddress            (DecodedInsn* d, ThumbOpcode op);
    void DecodeThumbAddToStackPointer      (DecodedInsn* d, ThumbOpcode op);
    void DecodeThumbPushPopRegisters       (DecodedInsn* d, ThumbOpcode op);
    void DecodeThumbMultipleLoadStore      (DecodedInsn* d, ThumbOpcode op);
    void DecodeThumbConditionalBranch      (DecodedInsn* d, ThumbOpcode op);

    bool DecodeArmUnconditional(DecodedInsn* insn, ArmOpcode op);

    bool DecodeArmBitfield(DecodedInsn* insn, ArmOpcode op);

    bool DecodeArmClass3Misc(DecodedInsn* insn, ArmOpcode op);

    bool DecodeArmLdrexStrex(DecodedInsn* insn, ArmOpcode op);

    ArmProcessorConfig*       processor_config_           = nullptr;
    ArmCpu*                   cpu_                        = nullptr;
    NeonUnconditionalDecoder* neon_unconditional_decoder_ = nullptr;
};
