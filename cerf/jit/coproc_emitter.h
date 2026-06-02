#pragma once

#include <cstdint>

#include "../core/service.h"

struct DecodedInsn;
struct BlockContext;

class CoprocEmitter : public Service {
public:
    using Service::Service;

    /* MRC / MCR — coprocessor register transfer. The implementation
       dispatches on d->cp_num and emits the per-coprocessor
       register-access body (or UND raise for absent coprocessors). */
    virtual uint8_t* EmitRegisterTransfer(uint8_t*      cursor,
                                          DecodedInsn*  d,
                                          BlockContext* ctx) = 0;

    /* LDC / STC — coprocessor data transfer (load/store coprocessor
       memory). Same call-site shape; per-cp_num dispatch lives in
       the concrete. */
    virtual uint8_t* EmitDataTransfer(uint8_t*      cursor,
                                      DecodedInsn*  d,
                                      BlockContext* ctx) = 0;

    /* CDP — coprocessor data operation. Same call-site shape. */
    virtual uint8_t* EmitDataOperation(uint8_t*      cursor,
                                       DecodedInsn*  d,
                                       BlockContext* ctx) = 0;

    /* MCRR / MRRC — v5TE two-register coprocessor move. Default raises
       guest UND; SoCs with a CP0/CP14 double-transfer (XScale acc0)
       override. Not pure-virtual so existing emitters inherit the UND. */
    virtual uint8_t* EmitRegisterTransferDouble(uint8_t*      cursor,
                                                DecodedInsn*  d,
                                                BlockContext* ctx);
};
