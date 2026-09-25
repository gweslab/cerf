#include "../vr41xx/vr41xx_kiu.h"

#include "../../boards/board_context.h"
#include "vr4111_id.h"
#include "../../core/cerf_emulator.h"

#include <cstdint>

namespace {

/* KIUSCANREP STPREP[5:0] 000000 is RFU (VR4111 UM 22.2.2 p463). Figure 22-3 p473 carries the
   SCANSTART auto-clear (Note 6), the KEYEN / SCANLINE interlock (Note 2, also 22.2.2 p463) and
   the deferred stop on KEYEN (Note 1). */
constexpr Vr41xxKiuModel kModel = {
    .stprep_zero_count        = 0u,
    .scanstart_auto_clear     = true,
    .keyen_scanline_interlock = true,
    .keyen_stop_deferred      = true,
    .gpen_retained_on_other_reset = true,
    .gpen_survives_kiurst         = true,
};

class Vr4111Kiu : public Vr41xxKiu {
public:
    using Vr41xxKiu::Vr41xxKiu;

    bool ShouldRegister() override {
        auto* bd = emu_.TryGet<BoardContext>();
        return bd && bd->GetSocId() == SocId::Vr4111;
    }

protected:
    const Vr41xxKiuModel& Model() const override { return kModel; }
};

}

REGISTER_SERVICE_AS(Vr4111Kiu, Vr41xxKiu);
