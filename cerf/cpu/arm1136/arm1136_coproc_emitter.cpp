#include "../../jit/coproc_emitter.h"

#define WIN32_LEAN_AND_MEAN
#define NOMINMAX
#include <windows.h>

#include <cstddef>

#include "../../core/cerf_emulator.h"
#include "../../jit/arm_jit.h"
#include "../../jit/cpu_state.h"
#include "../../jit/place_fns.h"
#include "../../jit/x86_emit.h"
#include "../../boards/board_detector.h"

namespace {

class Arm1136CoprocEmitter : public CoprocEmitter {
public:
    using CoprocEmitter::CoprocEmitter;

    bool ShouldRegister() override {
        auto* bd = emu_.TryGet<BoardDetector>();
        return bd && bd->GetBoard() == Board::ZuneKeel;
    }

    uint8_t* EmitRegisterTransfer(uint8_t*      cursor,
                                  DecodedInsn*  d,
                                  BlockContext* ctx) override {
        if (d->cp_num == 10 || d->cp_num == 11) {
            return EmitVfpRegisterTransfer(cursor, d, ctx);
        }
        if (d->cp_num != 15) {
            return EmitRaiseUndAndReturn(cursor, d, ctx);
        }

        /* ARM1136 TRM §3.3 Table 3-2 (p.3-19) MCR p15,0,Rd,c7,c0,4 =
           WFI.  Emit as no-op and the kernel idle MCR spins at JIT
           speed, burning a host core. */
        if (!d->l && d->crn == 7 && d->crm == 0 &&
            d->cp == 4 && d->cp_opc == 0) {
            using namespace x86;
            EmitMovRegImm32(cursor, kEcx,
                static_cast<uint32_t>(reinterpret_cast<uintptr_t>(ctx->jit)));
            EmitCall(cursor, reinterpret_cast<void*>(&ArmJit::WfiHelper));
            return cursor;
        }

        /* CRn=15 implementation-defined; iMX31 boot stub writes
           0x40000015 which would UND in shared dispatch.  Read
           returns 0; write is no-op. */
        if (d->crn == 15) {
            if (d->l) {
                using namespace x86;
                const int32_t rd_disp = static_cast<int32_t>(
                    offsetof(ArmCpuState, gprs) + d->rd * 4u);
                EmitMovBaseDisp32Imm32(cursor, kStateReg, rd_disp, 0u);
            }
            return cursor;
        }

        return EmitCp15RegisterTransfer(cursor, d, ctx);
    }

    uint8_t* EmitDataTransfer(uint8_t*      cursor,
                              DecodedInsn*  d,
                              BlockContext* ctx) override {
        if (d->cp_num == 10 || d->cp_num == 11) {
            return EmitVfpDataTransfer(cursor, d, ctx);
        }
        return EmitRaiseUndAndReturn(cursor, d, ctx);
    }

    uint8_t* EmitDataOperation(uint8_t*      cursor,
                               DecodedInsn*  d,
                               BlockContext* ctx) override {
        if (d->cp_num == 10 || d->cp_num == 11) {
            return EmitVfpDataOperation(cursor, d, ctx);
        }
        return EmitRaiseUndAndReturn(cursor, d, ctx);
    }
};

}  /* namespace */

REGISTER_SERVICE_AS(Arm1136CoprocEmitter, CoprocEmitter);
