#include "../xscale/xscale_coproc_emitter_base.h"

#define WIN32_LEAN_AND_MEAN
#define NOMINMAX
#include <windows.h>

#include <cstddef>

#include "../../core/cerf_emulator.h"
#include "../../jit/arm/arm_cpu.h"
#include "../../jit/arm/arm_emit_services.h"
#include "../../jit/arm/arm_interrupt_channel.h"
#include "../../jit/arm/arm_mmu_state.h"
#include "../../jit/arm/cpu_state.h"
#include "../../jit/arm/place_fns.h"
#include "../../jit/x86_emit.h"
#include "../../jit/x86_emit_alu.h"
#include "../../boards/board_context.h"

namespace {

class Pxa27xCoprocEmitter : public XscaleCoprocEmitterBase {
public:
    using XscaleCoprocEmitterBase::XscaleCoprocEmitterBase;

    bool ShouldRegister() override {
        auto* bd = emu_.TryGet<BoardContext>();
        return bd && bd->GetSoc() == SocFamily::PXA27x;
    }

    /* MK500c50BenOS013014.bin 0x801C2258 "MRC p1,0,r1,c1,c0,0", 0x801C2268
       "ANDS r1,r1,#3", 0x801C226C "BEQ 0x801C2280". */
    uint8_t* EmitRegisterTransfer(uint8_t*      cursor,
                                  DecodedInsn*  d,
                                  BlockContext* ctx) override {
        if (d->cp_num != 1u) {
            return XscaleCoprocEmitterBase::EmitRegisterTransfer(cursor, d, ctx);
        }
        cursor = EmitCparGate(cursor, d, ctx);
        if (d->l) {
            using namespace x86;
            const int32_t rd_disp = static_cast<int32_t>(
                offsetof(ArmCpuState, gprs) + d->rd * 4u);
            EmitMovBaseDisp32Imm32(cursor, kStateReg, rd_disp, 0u);
        }
        return cursor;
    }

protected:
    uint8_t* EmitPwrmodeWrite(uint8_t*      cursor,
                              uint8_t       m_field_reg,
                              DecodedInsn*  d,
                              BlockContext* ctx) override {
        using namespace x86;
        EmitCmpRegImm32(cursor, m_field_reg, 1u);
        uint8_t* is_idle = EmitJzLabel32(cursor);
        EmitCmpRegImm32(cursor, m_field_reg, 3u);
        uint8_t* is_sleep = EmitJzLabel32(cursor);
        EmitCmpRegImm32(cursor, m_field_reg, 7u);
        uint8_t* is_deep_sleep = EmitJzLabel32(cursor);
        EmitCmpRegImm32(cursor, m_field_reg, 0u);
        uint8_t* is_active = EmitJzLabel32(cursor);
        cursor = EmitCoprocUnimplementedFatal(cursor, d, ctx);

        FixupLabel32(is_idle, cursor);
        EmitMovRegImm32(cursor, kEcx,
            static_cast<uint32_t>(reinterpret_cast<uintptr_t>(
                ctx->emit->InterruptChannel())));
        EmitCall(cursor,
            reinterpret_cast<void*>(&ArmInterruptChannel::WfiHelper));
        uint8_t* idle_done = EmitJmpLabel32(cursor);

        FixupLabel32(is_sleep, cursor);
        FixupLabel32(is_deep_sleep, cursor);
        EmitMovRegImm32(cursor, kEcx,
            static_cast<uint32_t>(
                reinterpret_cast<uintptr_t>(ctx->emit->Cpu())));
        EmitCall(cursor,
            reinterpret_cast<void*>(&ArmCpu::EnterDeepSleepHelper));

        FixupLabel32(idle_done, cursor);
        FixupLabel32(is_active, cursor);
        return cursor;
    }

    /* Intel PXA27x Developer's Manual 280000-001 Section 2.2.5.4, Table 2-4
       (page 2-5): bits 13:0 CPn "0 = Access denied. Any attempt to access the
       corresponding coprocessor generates an undefined exception, even in
       supervisor mode."; reset row 0 for all 32 bits. */
    uint8_t* EmitCparGate(uint8_t*      cursor,
                          DecodedInsn*  d,
                          BlockContext* ctx) {
        using namespace x86;
        if (d->cp_num > 13u) return cursor;
        Emit8(cursor, 0xF7);
        EmitModRmReg(cursor, 2, kMmuReg, 0);
        Emit32(cursor, static_cast<uint32_t>(
            offsetof(ArmMmuState, coprocessor_access)));
        Emit32(cursor, 1u << d->cp_num);
        uint8_t* enabled = EmitJnzLabel(cursor);
        cursor = EmitRaiseUndAndReturn(cursor, d, ctx);
        FixupLabel(enabled, cursor);
        return cursor;
    }

    uint8_t* EmitUnhandledCoprocessor(uint8_t*      cursor,
                                      DecodedInsn*  d,
                                      BlockContext* ctx) override {
        cursor = EmitCparGate(cursor, d, ctx);
        return EmitCoprocUnimplementedFatal(cursor, d, ctx);
    }
};

}  /* namespace */

REGISTER_SERVICE_AS(Pxa27xCoprocEmitter, CoprocEmitter);
