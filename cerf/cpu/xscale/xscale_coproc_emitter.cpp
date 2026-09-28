#include "xscale_coproc_emitter_base.h"

#define WIN32_LEAN_AND_MEAN
#define NOMINMAX
#include <windows.h>

#include <cstddef>

#include "../../core/cerf_emulator.h"
#include "../../jit/arm/arm_cpu.h"
#include "../../jit/arm/arm_emit_services.h"
#include "../../jit/arm/arm_interrupt_channel.h"
#include "../../jit/arm/cpu_state.h"
#include "../../jit/arm/place_fns.h"
#include "../../jit/x86_emit.h"
#include "../../jit/x86_emit_alu.h"
#include "../../boards/board_context.h"
#include "../../socs/pxa255/pxa255_clock_manager.h"
#include "../../socs/pxa255/pxa255_id.h"

namespace {

class XscaleCoprocEmitter : public XscaleCoprocEmitterBase {
public:
    using XscaleCoprocEmitterBase::XscaleCoprocEmitterBase;

    bool ShouldRegister() override {
        auto* bd = emu_.TryGet<BoardContext>();
        return bd && bd->GetSocId() == SocId::Pxa255;
    }

protected:
    /* PXA255 Dev Man Table 3-25 PWRMODE M [1:0]: "00 - Run/turbo mode", "01 -
       Idle mode", "10 - reserved", "11 - Sleep mode"; [31:2] reserved. */
    uint8_t* EmitPwrmodeWrite(uint8_t*      cursor,
                              uint8_t       m_field_reg,
                              DecodedInsn*  d,
                              BlockContext* ctx) override {
        using namespace x86;
        EmitCmpRegImm32(cursor, m_field_reg, 1u);
        uint8_t* is_idle = EmitJzLabel32(cursor);
        EmitCmpRegImm32(cursor, m_field_reg, 3u);
        uint8_t* is_sleep = EmitJzLabel32(cursor);
        EmitCmpRegImm32(cursor, m_field_reg, 0u);
        uint8_t* is_run = EmitJzLabel32(cursor);
        cursor = EmitCoprocUnimplementedFatal(cursor, d, ctx);

        FixupLabel32(is_idle, cursor);
        EmitMovRegImm32(cursor, kEcx,
            static_cast<uint32_t>(reinterpret_cast<uintptr_t>(
                ctx->emit->InterruptChannel())));
        EmitCall(cursor,
            reinterpret_cast<void*>(&ArmInterruptChannel::WfiHelper));
        uint8_t* idle_done = EmitJmpLabel32(cursor);

        FixupLabel32(is_sleep, cursor);
        EmitMovRegImm32(cursor, kEcx,
            static_cast<uint32_t>(
                reinterpret_cast<uintptr_t>(ctx->emit->Cpu())));
        EmitCall(cursor,
            reinterpret_cast<void*>(&ArmCpu::EnterDeepSleepHelper));

        FixupLabel32(idle_done, cursor);
        FixupLabel32(is_run, cursor);
        return cursor;
    }

    /* PXA255 Dev Man Table 3-23: "Read CCLKCFG MRC p14, 0, Rd, c6, c0, 0",
       "Enter turbo mode ... MCR p14, 0, Rd, c6, c0, 0". */
    uint8_t* EmitClkcfgTransfer(uint8_t*      cursor,
                                DecodedInsn*  d,
                                BlockContext* ctx) override {
        using namespace x86;
        if (d->rd == 15u) return EmitCoprocUnimplementedFatal(cursor, d, ctx);
        const int32_t rd_disp = static_cast<int32_t>(
            offsetof(ArmCpuState, gprs) + d->rd * 4u);
        EmitMovRegImm32(cursor, kEcx,
            static_cast<uint32_t>(reinterpret_cast<uintptr_t>(
                &emu_.Get<Pxa255ClockManager>())));
        if (d->l) {
            EmitCall(cursor,
                reinterpret_cast<void*>(&Pxa255ClockManager::ReadClkcfgHelper));
            EmitMovBaseDisp32Reg(cursor, kStateReg, rd_disp, kEax);
        } else {
            EmitMovRegBaseDisp32(cursor, kEdx, kStateReg, rd_disp);
            EmitCall(cursor,
                reinterpret_cast<void*>(&Pxa255ClockManager::WriteClkcfgHelper));
        }
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
