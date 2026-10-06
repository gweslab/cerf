#include "../../peripherals/dallas_ds1386/ds1386_wiring.h"

#include "../../core/cerf_emulator.h"
#include "../../socs/vrc5477/vrc5477_giu.h"
#include "../board_context.h"
#include "nec_rockhopper_id.h"

namespace {

class NecRockhopperDs1386Wiring final : public Ds1386Wiring {
public:
    using Ds1386Wiring::Ds1386Wiring;

    bool ShouldRegister() override {
        return emu_.Get<BoardContext>().GetBoardId() == BoardId::NecRockhopper;
    }

    void OnReady() override { giu_ = &emu_.Get<Vrc5477Giu>(); }

    void SetIntA(bool active) override { giu_->DriveInterruptInput(active); }

    void SetIntB(bool) override {}

private:
    Vrc5477Giu* giu_ = nullptr;
};

REGISTER_SERVICE_AS(NecRockhopperDs1386Wiring, Ds1386Wiring);

}
