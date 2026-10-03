#include "ucb1x00_codec.h"

#include "../../boards/board_context.h"
#include "../../boards/philips_velo_1/philips_velo_1_id.h"
#include "../../boards/sharp_mobilon_hc4100/sharp_mobilon_hc4100_id.h"
#include "../../core/cerf_emulator.h"
#include "../../socs/pr31x00/pr31x00_ir.h"

namespace {

/* philips_velo_1_ce1 serial.dll sub_1EBAA5C and sharp_mobilon_hc4100_hpc2 SIB.dll
   sub_1542F6C pulse IR Control 1 RXPWR high, low, high before they read the codec ID. */
class Ucb1x00RxPwrResetPin : public Service {
public:
    using Service::Service;

    bool ShouldRegister() override {
        auto* bd = emu_.TryGet<BoardContext>();
        if (!bd) return false;
        const std::string_view b = bd->GetBoardId();
        return b == BoardId::PhilipsVelo1 || b == BoardId::SharpMobilonHc4100;
    }

    void OnReady() override {
        emu_.Get<Pr31x00Ir>().RegisterRxPwrObserver([this](bool level) {
            emu_.Get<Ucb1x00Codec>().DriveResetPin(level ? Ucb1x00Codec::ResetPin::High
                                                         : Ucb1x00Codec::ResetPin::Low);
        });
    }
};

}

REGISTER_SERVICE(Ucb1x00RxPwrResetPin);
