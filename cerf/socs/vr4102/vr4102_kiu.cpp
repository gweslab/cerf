#include "../vr41xx/vr41xx_kiu.h"

#include "../../boards/board_context.h"
#include "vr4102_id.h"
#include "../../core/cerf_emulator.h"

#include <cstdint>

namespace {

/* KIUSCANREP STPREP[5:0] 000000 is "64 times" (VR4102 UM 21.2.2 p425). Chapter 21 carries no
   sequencer figure: neither p425's D2 cell nor p426's bullet gives SCANSTART an automatic
   clear, p425's KEYEN cell carries no SCANLINE interlock, and p426 defers a stop only for
   SCANSTP, never for KEYEN. */
constexpr Vr41xxKiuModel kModel = {
    .stprep_zero_count        = 64u,
    .scanstart_auto_clear     = false,
    .keyen_scanline_interlock = false,
    .keyen_stop_deferred      = false,
    .gpen_retained_on_other_reset = false,
    .gpen_survives_kiurst         = false,
};

class Vr4102Kiu : public Vr41xxKiu {
public:
    using Vr41xxKiu::Vr41xxKiu;

    bool ShouldRegister() override {
        auto* bd = emu_.TryGet<BoardContext>();
        return bd && bd->GetSocId() == SocId::Vr4102;
    }

protected:
    const Vr41xxKiuModel& Model() const override { return kModel; }
};

}

REGISTER_SERVICE_AS(Vr4102Kiu, Vr41xxKiu);
