#include "../../peripherals/philips_ucb1200/ucb1x00_board.h"

#include "simpad_sl4_battery.h"
#include "simpad_sl4_keypad.h"
#include "../../peripherals/philips_ucb1200/ucb1x00_touch_panel.h"
#include "../board_context.h"
#include "simpad_sl4_id.h"
#include "../../core/cerf_emulator.h"
#include "../../core/fatal.h"
#include "../../socs/sa11xx/sa11xx_gpio.h"

#include <cstdint>
#include <cstdlib>

namespace {

/* simpad_sl4_ce4_10 touch.dll sub_1311F40 takes a sub_13119DC pressure reading of
   290 or more as pen down and updates the position above 290. */
constexpr uint16_t kPressureDown = 512u;
constexpr uint16_t kPressureUp   = 0u;

/* simpad_sl4_ce4_10 gwes.exe sub_ABA64 reports AC online when 1500 * AD2 / 51
   reaches 8500, from raw 289. */
constexpr uint16_t kAcOnlineAdc = 400u;

/* simpad_sl4_ce4_10 gwes.exe sub_ABA64 converts AD1 (battery) and AD2 (AC line)
   through sub_AB788, and flags charging when AD3 exceeds 0x32. */
constexpr uint8_t kAuxAd1 = 1;
constexpr uint8_t kAuxAd2 = 2;
constexpr uint8_t kAuxAd3 = 3;

/* SIMpad SL4 Technical Information §2.6: the battery charges from the power supply
   unit; §1.2: the charge LED goes out when it is full. */
constexpr uint16_t kChargeSenseActive = 0x200u;

constexpr uint32_t kUcbIrqGpio = 22;

uint16_t Clamp10(int v) { return static_cast<uint16_t>(v < 0 ? 0 : (v > 1023 ? 1023 : v)); }

/* simpad_sl4_ce4_10 touch.dll sub_1311F40 maps the sample average of sub_1312654 as
   X = n/16 + n/8 + n/4 + n/2 + 2n with n = raw - 48, Y = n/16 + n/4 + 2n with
   n = raw - 80. */
int TouchX(int n) { return n / 16 + n / 8 + n / 4 + n / 2 + 2 * n; }
int TouchY(int n) { return n / 16 + n / 4 + 2 * n; }

uint16_t InverseTouch(int px, int (*forward)(int), int num, int den, int base) {
    const int target = px < 0 ? 0 : px;
    const int guess  = (target * num + den / 2) / den;
    int best = guess;
    for (int n = guess - 1; n <= guess + 1; ++n) {
        if (n >= 0 && std::abs(forward(n) - target) < std::abs(forward(best) - target)) best = n;
    }
    return Clamp10(base + best);
}

uint16_t AdcX(int hx) { return InverseTouch(hx, TouchX, 16, 47, 48); }
uint16_t AdcY(int hy) { return InverseTouch(hy, TouchY, 16, 37, 80); }

/* simpad_sl4_ce4_10 gwes.exe sub_ABA64 averages AD1 as mV = 12600*(adc+21)/860 + 170.
   With HKLM\SOFTWARE\Version "Version" starting 'S' (sub_AB9D0) it shows 0..100%
   across 7200..8200 mV and powers off below 7200. */
uint16_t BatteryAdc(int pct) {
    if (pct < 0) pct = 0; else if (pct > 100) pct = 100;
    const int mv = 7200 + pct * 10;
    return Clamp10((mv - 170) * 860 / 12600 - 21);
}

class SimpadSl4UcbBoard : public Ucb1x00Board {
public:
    using Ucb1x00Board::Ucb1x00Board;

    bool ShouldRegister() override {
        auto* bd = emu_.TryGet<BoardContext>();
        return bd && bd->GetBoardId() == BoardId::SimpadSl4;
    }

    uint16_t AuxAdc(uint8_t channel) override {
        auto& batt = emu_.Get<SimpadSl4Battery>();
        if (channel == kAuxAd1) return BatteryAdc(batt.FillPercent());
        if (channel == kAuxAd2) return batt.IsOnBattery() ? 0u : kAcOnlineAdc;
        if (channel == kAuxAd3) {
            const bool charging = !batt.IsOnBattery() && batt.FillPercent() < 100;
            return charging ? kChargeSenseActive : 0u;
        }
        emu_.Get<Fatal>().Die("simpad: UCB AD%u conversion; nothing on this board is "
                              "modelled on that input", channel);
    }

    uint16_t TouchAdcX() override { return AdcX(emu_.Get<Ucb1x00TouchPanel>().X()); }
    uint16_t TouchAdcY() override { return AdcY(emu_.Get<Ucb1x00TouchPanel>().Y()); }
    uint16_t TouchAdcPressure() override {
        return emu_.Get<Ucb1x00TouchPanel>().Down() ? kPressureDown : kPressureUp;
    }

    /* simpad_sl4_ce4_10 keybddr.dll sub_13221BC reads IO_DATA through sub_13223D0(0)
       and keeps ~value & 0x3F, the six active-low button lines. */
    uint16_t IoInputs(uint16_t) override { return emu_.Get<SimpadSl4Keypad>().ReleasedIoBits(); }

    bool AdcExternalReference() const override { return false; }

    bool TsCrLowBitsSetOnTouch() const override { return true; }
    void OnIrqOutChanged(bool asserted) override {
        emu_.Get<Sa11xxGpio>().DriveInputPin(kUcbIrqGpio, asserted);
    }

    /* simpad_sl4_ce4_10 wavedev.dll WAV_PowerUp -> sub_1332038(0) writes reg 7 only
       through sub_133197C, which keeps AUD_GAIN bits 7-11; the gain writer sub_1331890
       runs from init sub_1331BF0 and from sub_1332FEC. */
    SocResetReach CodecSocResetReach() const override { return SocResetReach::Never; }
};

}  /* namespace */

REGISTER_SERVICE_AS(SimpadSl4UcbBoard, Ucb1x00Board);
