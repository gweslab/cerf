#include "xscale_coproc_emitter_base.h"

#include "../../boards/board_context.h"
#include "../../socs/iop13xx/iop13xx_id.h"
#include "../../core/cerf_emulator.h"
#include "../../jit/arm/arm_cpu.h"
#include "../../jit/arm/arm_emit_services.h"
#include "../../jit/arm/arm_interrupt_channel.h"
#include "../../jit/arm/place_fns.h"
#include "../../jit/x86_emit_alu.h"
#include "../../socs/iop13xx/iop13xx_cp6.h"

namespace {

class Iop13xxXscaleCoprocEmitter final : public XscaleCoprocEmitterBase {
public:
    using XscaleCoprocEmitterBase::XscaleCoprocEmitterBase;

    bool ShouldRegister() override {
        auto* bd = emu_.TryGet<BoardContext>();
        return bd && bd->GetSocId() == SocId::Iop13xx;
    }

    uint8_t* EmitRegisterTransfer(uint8_t* cursor, DecodedInsn* d, BlockContext* ctx) override {
        if (d->cp_num == 15 && !d->l && d->crn == 7 && d->cp_opc == 1) {
            const bool invalidate_mva = d->crm == 7 && d->cp == 1;
            const bool clean = d->crm == 11 && (d->cp == 1 || d->cp == 2);
            const bool clean_invalidate = d->crm == 15 && d->cp == 2;
            if (invalidate_mva || clean || clean_invalidate) return cursor;
        }
        if (d->cp_num == 6) {
            return static_cast<Iop13xxCp6&>(emu_.Get<IrqController>()).EmitRegisterTransfer(cursor, d, ctx);
        }
        /* Intel 81341/81342 Developer's Manual, tables 671-672. */
        if (d->cp_num == 7) return EmitCoprocUnimplementedFatal(cursor, d, ctx);
        return XscaleCoprocEmitterBase::EmitRegisterTransfer(cursor, d, ctx);
    }

protected:
    /* Third Generation Intel XScale Microarchitecture Developer's Manual Table
       66: M "0 = ACTIVE mode", "All other values are defined by the ASSP"; the
       Linux XSC3 model cpu_xsc3_do_idle writes M = 1 to "go to idle". */
    uint8_t* EmitPwrmodeWrite(uint8_t* cursor, uint8_t m_field_reg, DecodedInsn* d, BlockContext* ctx) override {
        using namespace x86;
        EmitCmpRegImm32(cursor, m_field_reg, 1u);
        uint8_t* is_idle = EmitJzLabel32(cursor);
        EmitCmpRegImm32(cursor, m_field_reg, 0u);
        uint8_t* is_active = EmitJzLabel32(cursor);
        cursor = EmitCoprocUnimplementedFatal(cursor, d, ctx);
        FixupLabel32(is_idle, cursor);
        EmitMovRegImm32(cursor, kEcx,
                       static_cast<uint32_t>(reinterpret_cast<uintptr_t>(ctx->emit->InterruptChannel())));
        EmitCall(cursor, reinterpret_cast<void*>(&ArmInterruptChannel::WfiHelper));
        FixupLabel32(is_active, cursor);
        return cursor;
    }

    uint8_t* EmitUnhandledCoprocessor(uint8_t* cursor, DecodedInsn* d, BlockContext* ctx) override {
        /* Intel 81341/81342 Developer's Manual, sections 21.3 and 21.8,
           tables 671-672. */
        if (d->cp_num == 6 || d->cp_num == 7 || d->cp_num == 14)
            return EmitCoprocUnimplementedFatal(cursor, d, ctx);
        return EmitRaiseUndAndReturn(cursor, d, ctx);
    }
};

} // namespace

REGISTER_SERVICE_AS(Iop13xxXscaleCoprocEmitter, CoprocEmitter);
