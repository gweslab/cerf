#include "nec_mobilepro_700_battery.h"

#include "../../core/cerf_emulator.h"
#include "../../host/host_widget_registry.h"
#include "../../peripherals/nec_vrc4172/vrc4172_gpio.h"
#include "../board_context.h"
#include "nec_mobilepro_700_id.h"

namespace {

/* nec_mobilepro_700_ce2 battdrv.dll BatteryDriverGetStatus 0x1560644: VRC4172 EXGPDATA0
   (kseg1 0xB5001080) bit 0x20 clear reports ACLineStatus online. */
constexpr int kOffAcPin = 5;

}

bool NecMobilePro700Battery::ShouldRegister() {
    auto* bd = emu_.TryGet<BoardContext>();
    return bd && bd->GetBoardId() == BoardId::NecMobilepro700;
}

void NecMobilePro700Battery::OnReady() {
    emu_.Get<HostWidgetRegistry>().Register(&battery_);
    battery_.SetChangeHandler([this] { DriveAcPin(); });
    DriveAcPin();
}

void NecMobilePro700Battery::DriveAcPin() {
    emu_.Get<Vrc4172Gpio>().SetPinLevel(kOffAcPin, battery_.IsOnBattery());
}

REGISTER_SERVICE(NecMobilePro700Battery);
