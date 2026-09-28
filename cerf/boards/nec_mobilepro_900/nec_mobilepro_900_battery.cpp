#include "nec_mobilepro_900_battery.h"

#include "../../core/cerf_emulator.h"
#include "../../host/host_widget_registry.h"
#include "../../socs/pxa255/pxa255_gpio.h"
#include "../board_context.h"
#include "nec_mobilepro_900_id.h"
#include "nec_mobilepro_900_pco_companion.h"

#include <cmath>

namespace {

/* GPIO inputs battery.dll reads from the CPU_GPIO block (PXA255 Dev Manual
   Table 4-49: GPLR0=0x40E00000, GPLR2=+0x08, GPDR2=+0x14, GAFR2_L=+0x64). */
constexpr uint32_t kGpioAcLine     = 77u;  /* GPLR2 bit13 (sub_1C8229C): high = on AC. */
constexpr uint32_t kGpioPresent    = 10u;  /* GPLR0 bit10 (sub_1C81F88): low forces NO_BATTERY. */
constexpr uint32_t kGpioConvBranch = 27u;  /* GPLR0 bit27 (sub_1C81F88): low selects the C5/C6 branch. */
/* nec_mobilepro_900_ce4_2 SABOOT.NB0 nk.exe sub_9006AF28: GPLR0 bit 6 high = "Battery Door closed". */
constexpr uint32_t kGpioDoorClosed = 6u;
/* nec_mobilepro_900_ce4_2 XIP.BIN pwr.dll sub_1BB19D0: GPLR0 bit 26 low at power-up
   signals EmergencyShutdownEvent (SYSINTR 25, thread sub_1BB1D98). */
constexpr uint32_t kGpioPowerGood  = 26u;

/* battery.dll voltage poly (sub_1C81F88) + table (0x1C842AC). */
constexpr double   kSlope       = 0.867924528;  /* C1*C2*1000 scaled-units per raw unit. */
constexpr double   kOffAc       = 6426.342525;  /* (C3 - C5 0.25) * 1000  - AC online. */
constexpr double   kOffBatt     = 6646.342525;  /* (C3 - C6 0.03) * 1000  - on battery. */
constexpr uint16_t kChargingBit = 0x8000u;      /* sub_1C8245C: value<0 => charging flag. */

/* Descending (scaled-threshold, percent) bands; the lookup picks the highest
   threshold the scaled value meets (sub_1C81F88 walk of 0x1C842AC). */
struct Band { uint16_t scaled; uint8_t percent; };
constexpr Band kBands[] = {
    {8010, 100}, {7910, 90}, {7820, 80}, {7740, 70}, {7670, 60}, {7590, 50},
    {7550, 40},  {7500, 30}, {7470, 20}, {7450, 10}, {7420, 0},
};

}  /* namespace */

bool NecMobilePro900Battery::ShouldRegister() {
    auto* bd = emu_.TryGet<BoardContext>();
    return bd && bd->GetBoardId() == BoardId::NecMobilepro900;
}

void NecMobilePro900Battery::OnReady() {
    battery_.SetChangeHandler([this] { DriveState(); });
    emu_.Get<HostWidgetRegistry>().Register(&battery_);
    DriveState();
}

uint16_t NecMobilePro900Battery::MainBatteryRaw(int fill_percent, bool on_ac) const {
    const Band* best = &kBands[0];
    int best_d = 1000;
    for (const Band& b : kBands) {
        int d = static_cast<int>(b.percent) - fill_percent;
        if (d < 0) d = -d;
        if (d < best_d) { best_d = d; best = &b; }
    }
    /* Land a few units inside the band so the threshold compare resolves to it. */
    const double scaled = static_cast<double>(best->scaled) + 8.0;
    const double off    = on_ac ? kOffAc : kOffBatt;
    long value = std::lround((scaled - off) / kSlope);
    if (value < 0)      value = 0;
    if (value > 0x7FFF) value = 0x7FFF;
    uint16_t raw = static_cast<uint16_t>(value);
    if (on_ac) raw |= kChargingBit;   /* charging on AC; also bypasses the force-100 path. */
    return raw;
}

void NecMobilePro900Battery::DriveState() {
    const bool on_battery = battery_.IsOnBattery();
    const bool on_ac      = !on_battery;

    auto& gpio = emu_.Get<Pxa255Gpio>();
    gpio.SetInputLevel(kGpioAcLine,     on_ac);
    gpio.SetInputLevel(kGpioPresent,    true);
    gpio.SetInputLevel(kGpioConvBranch, false);
    gpio.SetInputLevel(kGpioDoorClosed, true);
    gpio.SetInputLevel(kGpioPowerGood,  true);

    emu_.Get<NecMobilePro900PcoCompanion>().SetMainBatteryRaw(
        MainBatteryRaw(battery_.FillPercent(), on_ac));
}

REGISTER_SERVICE(NecMobilePro900Battery);
