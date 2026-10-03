#include "../../peripherals/philips_ucb1200/ucb1x00_sib_board.h"

#include "philips_velo_1_battery.h"
#include "../../peripherals/philips_ucb1200/ucb1x00_touch_panel.h"
#include "../board_context.h"
#include "philips_velo_1_id.h"
#include "../../core/cerf_emulator.h"
#include "../../core/fatal.h"
#include "../../core/log.h"

#include <cstdint>

namespace {

/* philips_velo_1_ce1 serial.dll sub_1EB9200 converts INP AD2 into shared word +40
   and INP AD3 into +54; gwes.exe sub_739B0 reads +40 as the main battery and +54
   as the backup cell. */
constexpr uint8_t kAuxMain   = 2;
constexpr uint8_t kAuxBackup = 3;

/* philips_velo_1_ce1 gwes.exe sub_739B0 flags the main average below 0x89 as no
   battery, from 0x141 HIGH, from 0x12D LOW, else CRITICAL. */
constexpr int kMainAdcEmpty = 0x89;
constexpr int kMainAdcFull  = 0x200;

/* philips_velo_1_ce1 gwes.exe sub_739B0 flags the backup cell below 0xD4 as no
   battery, from 0x16F HIGH, from 0x13C LOW, else CRITICAL. */
constexpr uint16_t kBackupAdcHealthy = 0x200;

uint16_t MainBatteryAdc(int fill_percent) {
    if (fill_percent < 0)   fill_percent = 0;
    if (fill_percent > 100) fill_percent = 100;
    const int raw = kMainAdcEmpty + fill_percent * (kMainAdcFull - kMainAdcEmpty) / 100;
    return static_cast<uint16_t>(raw);
}

uint16_t Clamp10(int v) { return static_cast<uint16_t>(v < 0 ? 0 : (v > 1023 ? 1023 : v)); }

/* philips_velo_1_ce1 touch.dll sub_1F211C0 passes the raw ADC pair to
   TouchPanelCalibrateAPoint. */
uint16_t PixelToAdc(int px) { return Clamp10(64 + (px < 0 ? 0 : px) * 2); }

constexpr uint16_t kPressureDown = 0x3FF;
constexpr uint16_t kPressureUp   = 0u;

class PhilipsVelo1UcbBoard : public Ucb1x00SibBoard {
public:
    using Ucb1x00SibBoard::Ucb1x00SibBoard;

    bool ShouldRegister() override {
        auto* bd = emu_.TryGet<BoardContext>();
        return bd && bd->GetBoardId() == BoardId::PhilipsVelo1;
    }

    uint16_t AuxAdc(uint8_t channel) override {
        switch (channel) {
            case kAuxMain:   return MainBatteryAdc(emu_.Get<PhilipsVelo1Battery>().FillPercent());
            case kAuxBackup: return kBackupAdcHealthy;
            default:
                LOG(Caution, "PhilipsVelo1UcbBoard: aux ADC channel %u unmodeled\n", channel);
                CerfFatalExit(CERF_FATAL_RUNTIME_ERROR);
        }
    }

    uint16_t TouchAdcX() override { return PixelToAdc(emu_.Get<Ucb1x00TouchPanel>().X()); }
    uint16_t TouchAdcY() override { return PixelToAdc(emu_.Get<Ucb1x00TouchPanel>().Y()); }
    uint16_t TouchAdcPressure() override {
        return emu_.Get<Ucb1x00TouchPanel>().Down() ? kPressureDown : kPressureUp;
    }

    uint16_t IoInputs(uint16_t input_mask) override {
        emu_.Get<Fatal>().Die("velo: UCB IO_DATA read with input pins 0x%03X; no codec I/O "
                              "input is modelled on this board", input_mask);
    }

    bool AdcExternalReference() const override { return true; }

    bool TsCrLowBitsSetOnTouch() const override { return true; }

    SocResetReach CodecSocResetReach() const override { return SocResetReach::Unknown; }
};

}  /* namespace */

REGISTER_SERVICE_AS(PhilipsVelo1UcbBoard, Ucb1x00Board);
