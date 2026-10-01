#include "imx31_gpio1.h"

#include "imx31_avic.h"

#include <cstdint>

namespace {

/* MCIMX31RM Table 2-3: interrupt 52, GPIO1 module. */
constexpr uint32_t kAvicSourceGpio1 = 52u;

}

void Imx31Gpio1::DrivePortIrqLine(bool asserted) {
    auto& avic = emu_.Get<Imx31Avic>();
    if (asserted) avic.AssertSource(kAvicSourceGpio1);
    else          avic.DeassertSource(kAvicSourceGpio1);
}

REGISTER_SERVICE(Imx31Gpio1);
