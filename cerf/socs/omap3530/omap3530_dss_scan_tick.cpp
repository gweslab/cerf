#include "omap3530_dss.h"

#include "../../boards/board_detector.h"
#include "../../core/cerf_emulator.h"
#include "../../host/lcd_scan_tick.h"

namespace {

class Omap3530DssScanTick : public LcdScanTick {
public:
    using LcdScanTick::LcdScanTick;

    bool ShouldRegister() override {
        auto* bd = emu_.TryGet<BoardDetector>();
        return bd && bd->GetSoc() == SocFamily::OMAP3530;
    }

    void OnHostTick() override {
        emu_.Get<Omap3530Dss>().AdvanceScanTick();
    }
};

}  /* namespace */

REGISTER_SERVICE_AS(Omap3530DssScanTick, LcdScanTick);
