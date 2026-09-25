#include "irq_controller.h"

#include "../core/cerf_emulator.h"
#include "../core/fatal.h"

uint32_t IrqController::ReadPendingVector() {
    emu_.Get<Fatal>().Die(
        "irq controller: the core read a vectored-interrupt pending vector, "
        "but this interrupt controller has no vectored interface");
}

void IrqController::PulseIrq(int source_bit) {
    emu_.Get<Fatal>().Die(
        "irq controller: source %d delivered a zero-width pulse, and this "
        "interrupt controller has no modeled response to one", source_bit);
}

uint32_t __fastcall IrqController::ReadPendingVectorHelper(IrqController* intc) {
    return intc->ReadPendingVector();
}
