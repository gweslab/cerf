#include "pr31x00_ir.h"

#include "../../boards/board_context.h"
#include "pr31500_id.h"
#include "pr31700_id.h"
#include "../../core/cerf_emulator.h"
#include "../../peripherals/peripheral_dispatcher.h"
#include "../../state/state_stream.h"
#include "pr31x00_intc.h"

#include <cstdint>

namespace {

constexpr uint32_t kBase = 0x10C000A0u;

/* IR Control 1 (§10.5.1): CARDET<24>(R) BAUDVAL[7:0]<23:16> TESTIR<4> DTINVERT<3>
   RXPWR<2> ENSTATE<1> ENCONSM<0>; bits 31-25 and 15-5 reserved. */
constexpr uint32_t kCtl1Reserved = 0xFE00FFE0u;

/* TESTIR "should not be set" (§10.5.1); ENSTATE starts the carrier detect state
   machine and ENCONSM the Consumer IR function, both of which clock the Period
   Width and OnTime Width counters against a transceiver. */
constexpr uint32_t kCtl1Unmodeled = 0x00000013u;

/* BAUDVAL pre-scales IRCLK, DTINVERT inverts IROUT and RXPWR drives the RXPWR pin;
   none of them moves a frame while the state machines are off. */
constexpr uint32_t kCtl1Writable = 0x00FF000Cu;

/* CARDET<24>, "the status of the CARDET (carrier detect) input pin" (§10.5.1). */
constexpr uint32_t kCtl1CarDet = 1u << 24;

/* Interrupt Status 5 (§8.3.5): POSCARINT<15> is set on a CARDET 0->1 transition and
   NEGCARINT<14> on a 1->0 transition. */
constexpr uint32_t kStatus5Set    = 4u;
constexpr uint32_t kPosCarInt     = 1u << 15;
constexpr uint32_t kNegCarInt     = 1u << 14;

}  /* namespace */

bool Pr31x00Ir::ShouldRegister() {
    auto* bd = emu_.TryGet<BoardContext>();
    if (!bd) return false;
    const std::string_view soc = bd->GetSocId();
    return soc == SocId::Pr31500 || soc == SocId::Pr31700;
}

void Pr31x00Ir::OnReady() {
    emu_.Get<PeripheralDispatcher>().Register(this);
}

uint32_t Pr31x00Ir::ReadWord(uint32_t addr) {
    if (addr != kBase) {
        HaltUnsupportedAccess("PR31x00 IR_CTL1 ReadWord", addr, 0);
    }
    return ctl1_ | (cardet_.load(std::memory_order_acquire) ? kCtl1CarDet : 0u);
}

void Pr31x00Ir::WriteWord(uint32_t addr, uint32_t value) {
    if (addr != kBase) {
        HaltUnsupportedAccess("PR31x00 IR_CTL1 WriteWord", addr, value);
    }
    if (value & kCtl1Reserved) {
        HaltUnsupportedAccess("PR31x00 IR_CTL1 reserved", addr, value);
    }
    if (value & kCtl1Unmodeled) {
        HaltUnsupportedAccess("PR31x00 IR_CTL1 arms the IR state machines", addr, value);
    }
    ctl1_ = value & kCtl1Writable;   /* CARDET is read-only */
}

void Pr31x00Ir::DriveCarDetInput(bool level) {
    const bool old = cardet_.exchange(level, std::memory_order_acq_rel);
    if (old == level) return;
    emu_.Get<Pr31x00Intc>().SetPending(kStatus5Set, level ? kPosCarInt : kNegCarInt);
}

void Pr31x00Ir::SaveState(StateWriter& w) {
    w.Write("ctl1", ctl1_);
    w.Write<uint8_t>("cardet", cardet_.load(std::memory_order_acquire) ? 1u : 0u);
}

void Pr31x00Ir::RestoreState(StateReader& r) {
    r.Read("ctl1", ctl1_);
    uint8_t cardet = 0;
    r.Read("cardet", cardet);
    cardet_.store(cardet != 0u, std::memory_order_release);
}

REGISTER_SERVICE(Pr31x00Ir);
