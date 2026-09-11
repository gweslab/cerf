#include "siemens_mp377_debug_led_peripheral.h"
#include "siemens_mp377_debug_leds.h"
#include "../../core/cerf_emulator.h"
#include "../../state/state_stream.h"

namespace {
class SiemensMp377DebugLedTickRegister final : public SiemensMp377DebugLedPeripheral {
public:
    using SiemensMp377DebugLedPeripheral::SiemensMp377DebugLedPeripheral;

    uint32_t MmioBase() const override { return siemens_mp377::kDebugLedTickBase; }
    uint32_t MmioSize() const override { return siemens_mp377::kDebugLedTickEnd - MmioBase(); }

    void WriteHalf(uint32_t addr, uint16_t value) override {
        if (addr == siemens_mp377::kDebugLedTickBase) {
            value_ = value;
            return;
        }
        SiemensMp377DebugLedPeripheral::WriteHalf(addr, value);
    }

    void SaveState(StateWriter& w) override { w.Write(value_); }
    void RestoreState(StateReader& r) override { r.Read(value_); }

private:
    uint16_t value_{};
};
} // namespace
REGISTER_SERVICE(SiemensMp377DebugLedTickRegister);
