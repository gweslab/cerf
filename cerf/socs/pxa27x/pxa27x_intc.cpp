#include "../pxa2xx/pxa2xx_intc.h"

#include "../../boards/board_context.h"
#include "../../core/cerf_emulator.h"

namespace {

class Pxa27xIntc : public Pxa2xxIntc {
public:
    using Pxa2xxIntc::Pxa2xxIntc;

    bool ShouldRegister() override {
        auto* bd = emu_.TryGet<BoardContext>();
        return bd && bd->GetSoc() == SocFamily::PXA27x;
    }

protected:
    /* Intel PXA27x Developer's Manual 280000-001 Table 25-16: ICIP2 0x9C,
       ICMR2 0xA0, ICLR2 0xA4, ICFP2 0xA8, ICPR2 0xAC. Table 25-2: IP[33] Quick
       capture interface is the only assigned second-bank source. */
    bool HasSecondBank() const override { return true; }
};

}

REGISTER_SERVICE_AS(Pxa27xIntc, IrqController);
