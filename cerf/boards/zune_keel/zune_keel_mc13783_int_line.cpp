#include "../../core/cerf_emulator.h"
#include "../../peripherals/freescale_mc13783/mc13783_int_line.h"
#include "../../socs/imx31/imx31_gpio1.h"
#include "../board_context.h"
#include "zune_30_id.h"

#include <cstdint>

namespace {

/* zune_keel nk.exe sub_8823E33C: clears GPIO1 ISR bit 31, sets IMR bit 31, and reads the
   MC13783 status while AVIC source 52 is pending. */
constexpr uint32_t kPmicIntGpio1Pin = 31u;

class ZuneKeelMc13783IntLine : public Mc13783IntLine {
public:
    using Mc13783IntLine::Mc13783IntLine;

    bool ShouldRegister() override {
        return emu_.Get<BoardContext>().GetBoardId() == BoardId::Zune30;
    }

    void OnReady() override { SetMc13783IntAsserted(false); }

    /* MC13783 UG §3.4.1: PRIINT is driven high on an interrupt. Rockbox Gigabeat S
       gpio-target.h: GPIO_EVENT_VECTOR(GPIO1_31, GPIO_SENSE_HIGH_LEVEL). */
    void SetMc13783IntAsserted(bool asserted) override {
        emu_.Get<Imx31Gpio1>().SetInputPin(kPmicIntGpio1Pin, asserted);
    }
};

}

REGISTER_SERVICE_AS(ZuneKeelMc13783IntLine, Mc13783IntLine);
