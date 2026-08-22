#pragma once

#include <cstdint>

#include "../../jit/arm/coproc_emitter.h"

struct DecodedInsn;
struct BlockContext;

class XscaleCoprocEmitterBase : public CoprocEmitter {
public:
    using CoprocEmitter::CoprocEmitter;

    uint8_t* EmitRegisterTransfer(uint8_t*      cursor,
                                  DecodedInsn*  d,
                                  BlockContext* ctx) override;

    uint8_t* EmitDataTransfer(uint8_t*      cursor,
                              DecodedInsn*  d,
                              BlockContext* ctx) override;

    uint8_t* EmitDataOperation(uint8_t*      cursor,
                               DecodedInsn*  d,
                               BlockContext* ctx) override;

    uint8_t* EmitRegisterTransferDouble(uint8_t*      cursor,
                                        DecodedInsn*  d,
                                        BlockContext* ctx) override;

protected:
    virtual uint8_t* EmitPwrmodeWrite(uint8_t*      cursor,
                                      uint8_t       m_field_reg,
                                      DecodedInsn*  d,
                                      BlockContext* ctx) = 0;

    virtual uint8_t* EmitUnhandledCoprocessor(uint8_t*      cursor,
                                              DecodedInsn*  d,
                                              BlockContext* ctx) = 0;
};
