#include "../../peripherals/philips_ucb1200/ucb1x00_sib_board.h"

#include "philips_nino_300_battery.h"
#include "../../peripherals/philips_ucb1200/ucb1x00_touch_panel.h"
#include "../board_context.h"
#include "philips_nino_300_id.h"
#include "../../core/cerf_emulator.h"
#include "../../core/log.h"

#include <cstdint>

namespace {

[[noreturn]] void Unwired(const char* what) {
    LOG(Caution, "PhilipsNino300UcbBoard: %s is not wired to the codec\n", what);
    CerfFatalExit(CERF_FATAL_RUNTIME_ERROR);
}

/* philips_nino_300 gwes.exe sub_82C18 issues SIB1 IOCTL 1 with nInBufSize 0 (main
   battery), 2 (backup cell) and 3 (battery-type sense). */
constexpr uint8_t kAuxMain      = 0;   /* AD0 */
constexpr uint8_t kAuxBackup    = 2;   /* AD2 */
constexpr uint8_t kAuxChemistry = 3;   /* AD3 */

/* philips_nino_300 gwes.exe sub_83088 bands the AD0 average against ControlPanel\
   Battery\Alkaline MainNotLow/MainLow/MainNotCritical/MainCritical, in-image defaults
   0x170/0x140/0x139/0x12C at 0x84A64. */
constexpr int kMainAdcEmpty = 0x100;
constexpr int kMainAdcFull  = 0x200;

/* philips_nino_300 gwes.exe sub_82FE4 reports the AD2 backup cell HIGH at raw >= 0x13C
   when its previous flag was not LOW. */
constexpr uint16_t kBackupAdcHealthy = 0x200;

/* philips_nino_300 gwes.exe sub_82C18 selects the Alkaline threshold set when
   AD3 < 0x104, else NiMH. */
constexpr uint16_t kChemistryAlkalineAdc = 0x80;

/* philips_nino_300 touch.dll sub_1891B84 compares the averaged reading with
   word_18B5960, ControlPanel\Touch "Threshhold" (default 90). */
constexpr uint16_t kPressureDown = 0x3FF;
constexpr uint16_t kPressureUp   = 0u;

uint16_t Clamp10(int v) { return static_cast<uint16_t>(v < 0 ? 0 : (v > 1023 ? 1023 : v)); }

uint16_t PixelToAdc(int px) { return Clamp10(64 + (px < 0 ? 0 : px) * 3); }

uint16_t MainBatteryAdc(int fill_percent) {
    if (fill_percent < 0)   fill_percent = 0;
    if (fill_percent > 100) fill_percent = 100;
    const int raw = kMainAdcEmpty +
                    fill_percent * (kMainAdcFull - kMainAdcEmpty) / 100;
    return static_cast<uint16_t>(raw);
}

class PhilipsNino300UcbBoard : public Ucb1x00SibBoard {
public:
    using Ucb1x00SibBoard::Ucb1x00SibBoard;

    bool ShouldRegister() override {
        auto* bd = emu_.TryGet<BoardContext>();
        return bd && bd->GetBoardId() == BoardId::PhilipsNino300;
    }

    uint16_t AuxAdc(uint8_t channel) override {
        switch (channel) {
            case kAuxMain:
                return MainBatteryAdc(emu_.Get<PhilipsNino300Battery>().FillPercent());
            case kAuxBackup:    return kBackupAdcHealthy;
            case kAuxChemistry: return kChemistryAlkalineAdc;
            default:            Unwired("an auxiliary ADC channel");
        }
    }

    uint16_t TouchAdcX() override { return PixelToAdc(emu_.Get<Ucb1x00TouchPanel>().X()); }
    uint16_t TouchAdcY() override { return PixelToAdc(emu_.Get<Ucb1x00TouchPanel>().Y()); }
    uint16_t TouchAdcPressure() override {
        return emu_.Get<Ucb1x00TouchPanel>().Down() ? kPressureDown : kPressureUp;
    }

    /* philips_nino_300 sib.dll sub_18D1654 writes IO_DIR = 0x83FF, driving all ten
       I/O ports (NetBSD hpcmips ucb1200reg.h UCB1200_IOPORT_MAX 10), so the port reads
       back what the driver drives. sub_18D14E0 idles a subframe with a read of it. */
    /* philips_nino_300 sib.dll sub_18D14E0(0) reads IO_DATA while every pin is an input
       and never takes the result from SF0STAT. */
    uint16_t IoInputs(uint16_t) override { return 0u; }

    bool AdcExternalReference() const override { return false; }

    bool TsCrLowBitsSetOnTouch() const override { return true; }

    SocResetReach CodecSocResetReach() const override { return SocResetReach::Unknown; }
};

}  /* namespace */

REGISTER_SERVICE_AS(PhilipsNino300UcbBoard, Ucb1x00Board);
