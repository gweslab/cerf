#include "xscale_coproc_emitter_base.h"

#define WIN32_LEAN_AND_MEAN
#define NOMINMAX
#include <windows.h>

#include "../../core/cerf_emulator.h"
#include "../../jit/arm/arm_cpu.h"
#include "../../jit/arm/arm_emit_services.h"
#include "../../jit/arm/arm_interrupt_channel.h"
#include "../../jit/arm/place_fns.h"
#include "../../jit/x86_emit_alu.h"
#include "../../boards/board_context.h"

namespace {

class XscaleCoprocEmitter : public XscaleCoprocEmitterBase {
public:
    using XscaleCoprocEmitterBase::XscaleCoprocEmitterBase;

    bool ShouldRegister() override {
        auto* bd = emu_.TryGet<BoardContext>();
        return bd && bd->GetSoc() == SocFamily::PXA25x;
    }

protected:
    /* PWRMODE M=bits[3:0] - XScale Core Dev Manual Table 7-23. M=1 IDLE
       (OEMIdle sub_800F736C) halts till the next IRQ; M=3 SLEEP
       (OEMPowerOff sub_800F73B0) is a real power-down - notify the user,
       then park. */
    uint8_t* EmitPwrmodeWrite(uint8_t*      cursor,
                              uint8_t       m_field_reg,
                              DecodedInsn*,
                              BlockContext* ctx) override {
        using namespace x86;
        EmitCmpRegImm32(cursor, m_field_reg, 3u);
        uint8_t* not_sleep = EmitJnzLabel(cursor);
        EmitMovRegImm32(cursor, kEcx,
            static_cast<uint32_t>(
                reinterpret_cast<uintptr_t>(ctx->emit->Cpu())));
        EmitCall(cursor,
            reinterpret_cast<void*>(&ArmCpu::EnterDeepSleepHelper));
        uint8_t* done = EmitJmpLabel(cursor);
        FixupLabel(not_sleep, cursor);
        EmitMovRegImm32(cursor, kEcx,
            static_cast<uint32_t>(reinterpret_cast<uintptr_t>(
                ctx->emit->InterruptChannel())));
        EmitCall(cursor,
            reinterpret_cast<void*>(&ArmInterruptChannel::WfiHelper));
        FixupLabel(done, cursor);
        return cursor;
    }

    uint8_t* EmitUnhandledCoprocessor(uint8_t*      cursor,
                                      DecodedInsn*  d,
                                      BlockContext* ctx) override {
        return EmitRaiseUndAndReturn(cursor, d, ctx);
    }
};

}  /* namespace */

REGISTER_SERVICE_AS(XscaleCoprocEmitter, CoprocEmitter);
