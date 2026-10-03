#include "pr31x00_sib_irq_pin.h"

#include "../../boards/board_context.h"
#include "../../core/cerf_emulator.h"
#include "pr31500_id.h"
#include "pr31700_id.h"
#include "pr31x00_intc.h"

#include <cstdint>

namespace {

/* NetBSD hpcmips tx39icureg.h TX39_INTRSTATUS1_SIBIRQPOSINT 0x40, SIBIRQNEGINT 0x20. */
constexpr uint32_t kStatus1      = 0;
constexpr uint32_t kSibIrqPosInt = 1u << 6;
constexpr uint32_t kSibIrqNegInt = 1u << 5;

}

bool Pr31x00SibIrqPin::ShouldRegister() {
    const std::string_view soc = emu_.Get<BoardContext>().GetSocId();
    return soc == SocId::Pr31500 || soc == SocId::Pr31700;
}

void Pr31x00SibIrqPin::OnPinEdge(bool rising) {
    emu_.Get<Pr31x00Intc>().SetPending(kStatus1, rising ? kSibIrqPosInt : kSibIrqNegInt);
}

REGISTER_SERVICE(Pr31x00SibIrqPin);
