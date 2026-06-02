#include "../../jit/coproc_emitter.h"

#include <cstddef>

#include "../../core/cerf_emulator.h"
#include "../../jit/arm_mmu_state.h"
#include "../../jit/cpu_state.h"
#include "../../jit/place_fns.h"
#include "../../jit/x86_emit.h"
#include "../../boards/board_detector.h"

namespace {

class S3C2410CoprocEmitter : public CoprocEmitter {
public:
    using CoprocEmitter::CoprocEmitter;

    bool ShouldRegister() override {
        auto* bd = emu_.TryGet<BoardDetector>();
        return bd && bd->GetSoc() == SocFamily::S3C2410;
    }

    uint8_t* EmitRegisterTransfer(uint8_t*      cursor,
                                  DecodedInsn*  d,
                                  BlockContext* ctx) override {
        if (d->cp_num == 15) {
            if (d->crn == 15) {
                return EmitCp15Cacr(cursor, d, ctx);
            }
            /* ARM920T CRP write (c1/c1): only bits[5:4]|[1:0] may be
               set; P (bit 1) required.  Other Aux Control Register
               layouts (ARM1136, Cortex-A8) reach the shared path's
               store-only branch. */
            if (d->crn == 1 && !d->l && d->cp == 1) {
                using namespace x86;
                const int32_t rd_disp = static_cast<int32_t>(
                    offsetof(ArmCpuState, gprs) + d->rd * 4u);
                EmitMovRegBaseDisp32(cursor, kEax, kStateReg, rd_disp);
                EmitTestRegImm32(cursor, kEax, 0xFFFFFFCCu);
                uint8_t* raise_label = EmitJnzLabel(cursor);
                EmitTestRegImm32(cursor, kEax, 2u);
                uint8_t* store_label = EmitJnzLabel(cursor);
                FixupLabel(raise_label, cursor);
                cursor = EmitRaiseUndAndReturn(cursor, d, ctx);
                FixupLabel(store_label, cursor);
                EmitMovBaseDisp32Reg(cursor, kMmuReg, static_cast<int32_t>(
                    offsetof(ArmMmuState, aux_control_register)), kEax);
                return cursor;
            }
            return EmitCp15RegisterTransfer(cursor, d, ctx);
        }
        return EmitRaiseUndAndReturn(cursor, d, ctx);
    }

    uint8_t* EmitDataTransfer(uint8_t*      cursor,
                              DecodedInsn*  d,
                              BlockContext* ctx) override {
        return EmitRaiseUndAndReturn(cursor, d, ctx);
    }

    uint8_t* EmitDataOperation(uint8_t*      cursor,
                               DecodedInsn*  d,
                               BlockContext* ctx) override {
        return EmitRaiseUndAndReturn(cursor, d, ctx);
    }
};

}  /* namespace */

REGISTER_SERVICE_AS(S3C2410CoprocEmitter, CoprocEmitter);
