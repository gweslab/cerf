#include "../pxa2xx/pxa2xx_intc.h"

#include "../../boards/board_context.h"
#include "../../core/cerf_emulator.h"

namespace {

class Pxa255Intc : public Pxa2xxIntc {
public:
    using Pxa2xxIntc::Pxa2xxIntc;

    bool ShouldRegister() override {
        auto* bd = emu_.TryGet<BoardContext>();
        return bd && bd->GetSoc() == SocFamily::PXA25x;
    }

protected:
    bool HasSecondBank() const override { return false; }
};

}

REGISTER_SERVICE_AS(Pxa255Intc, IrqController);
