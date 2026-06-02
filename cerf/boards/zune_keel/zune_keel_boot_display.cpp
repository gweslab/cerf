#include "../board_detector.h"
#include "zune_keel_framebuffer.h"

#include "../../core/cerf_emulator.h"
#include "../../core/log.h"
#include "../../core/service.h"
#include "../../socs/imx31/imx31_ipu.h"

namespace {

class ZuneKeelBootDisplay : public Service {
public:
    using Service::Service;

    bool ShouldRegister() override {
        auto* bd = emu_.TryGet<BoardDetector>();
        return bd && bd->GetBoard() == Board::ZuneKeel;
    }

    void OnReady() override {
        /* No bootloader runs under CERF, so the board brings up the IPU SDC
           scan-out itself; the OS display driver later reprograms it via MMIO. */
        emu_.Get<Imx31Ipu>().SetupSdcScanout(
            zune_keel::kFbPa, zune_keel::kScreenW, zune_keel::kScreenH);
        LOG(Board, "ZuneKeelBootDisplay: IPU SDC scan-out %ux%u RGB565 @ PA 0x%08X\n",
            zune_keel::kScreenW, zune_keel::kScreenH, zune_keel::kFbPa);
    }
};

}  /* namespace */

REGISTER_SERVICE(ZuneKeelBootDisplay);
