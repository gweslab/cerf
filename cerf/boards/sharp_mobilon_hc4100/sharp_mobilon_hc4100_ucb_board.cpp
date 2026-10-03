#include "../../peripherals/philips_ucb1200/ucb1x00_sib_board.h"

#include "sharp_mobilon_hc4100_battery.h"
#include "../../peripherals/philips_ucb1200/ucb1x00_touch_panel.h"
#include "../board_context.h"
#include "sharp_mobilon_hc4100_id.h"
#include "../../core/cerf_emulator.h"
#include "../../core/log.h"

#include <cstdint>

namespace {

[[noreturn]] void Unwired(const char* what) {
    LOG(Caution, "SharpMobilonHc4100UcbBoard: %s not yet grounded\n", what);
    CerfFatalExit(CERF_FATAL_RUNTIME_ERROR);
}

uint16_t Clamp10(int v) { return static_cast<uint16_t>(v < 0 ? 0 : (v > 1023 ? 1023 : v)); }

/* sharp_mobilon_hc4100_hpc2 touch.dll sub_14A1170 passes the raw ADC pair to
   TouchPanelCalibrateAPoint. */
uint16_t PixelToAdc(int px) { return Clamp10(64 + (px < 0 ? 0 : px)); }

constexpr uint16_t kPressureDown = 0x3FF;
constexpr uint16_t kPressureUp   = 0u;

/* sharp_mobilon_hc4100_hpc2 gwes.exe sub_9F38C samples AD3 (backup) and AD0 or AD2
   (main); sub_9F0E4 bands 75*raw>>10 against row byte_ABB38 = 0 of the table at
   0x156D0, {22, 20}: HIGH from raw 315, CRITICAL up to raw 286. */
constexpr int      kMainAdcEmpty     = 0x100;
constexpr int      kMainAdcFull      = 0x200;
constexpr uint16_t kBackupAdcHealthy = 0x200;

uint16_t MainBatteryAdc(int fill_percent) {
    if (fill_percent < 0)   fill_percent = 0;
    if (fill_percent > 100) fill_percent = 100;
    return static_cast<uint16_t>(
        kMainAdcEmpty + fill_percent * (kMainAdcFull - kMainAdcEmpty) / 100);
}

class SharpMobilonHc4100UcbBoard : public Ucb1x00SibBoard {
public:
    using Ucb1x00SibBoard::Ucb1x00SibBoard;

    bool ShouldRegister() override {
        auto* bd = emu_.TryGet<BoardContext>();
        return bd && bd->GetBoardId() == BoardId::SharpMobilonHc4100;
    }

    uint16_t AuxAdc(uint8_t channel) override {
        switch (channel) {
            case 0:
            case 2:
                return MainBatteryAdc(emu_.Get<SharpMobilonHc4100Battery>().FillPercent());
            case 3:
                return kBackupAdcHealthy;
            default:
                Unwired("AuxAdc");
        }
    }
    uint16_t TouchAdcX() override { return PixelToAdc(emu_.Get<Ucb1x00TouchPanel>().X()); }
    uint16_t TouchAdcY() override { return PixelToAdc(emu_.Get<Ucb1x00TouchPanel>().Y()); }
    uint16_t TouchAdcPressure() override {
        return emu_.Get<Ucb1x00TouchPanel>().Down() ? kPressureDown : kPressureUp;
    }
    /* sharp_mobilon_hc4100_hpc2 ddi.dll sub_1481C14 is the IO_DATA reader: it writes the
       read value back through SIB.dll IOCTL 19 with mask 0x1F, dropping input pin 8. */
    uint16_t IoInputs(uint16_t) override { return 0u; }

    bool AdcExternalReference() const override { return false; }

    bool TsCrLowBitsSetOnTouch() const override { return true; }

    SocResetReach CodecSocResetReach() const override { return SocResetReach::Unknown; }
};

}  /* namespace */

REGISTER_SERVICE_AS(SharpMobilonHc4100UcbBoard, Ucb1x00Board);
