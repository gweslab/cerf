#include "ucb1x00_sib_board.h"

#include "../../core/cerf_emulator.h"
#include "../../socs/pr31x00/pr31x00_sib_irq_pin.h"

void Ucb1x00SibBoard::OnIrqOutChanged(bool asserted) {
    emu_.Get<Pr31x00SibIrqPin>().OnPinEdge(asserted);
}
