#include "cerf_virt_addr_map.h"
#include "cerf_virt_tick_profiler_regs.h"

#include "../peripheral_base.h"
#include "../peripheral_dispatcher.h"
#include "../../boards/board_context.h"
#include "../../core/cerf_emulator.h"
#include "../../core/device_config.h"
#include "../../core/virtual_clock.h"

namespace {

class CerfVirtTickProfiler : public Peripheral {
public:
    using Peripheral::Peripheral;

    bool ShouldRegister() override {
        return emu_.Get<DeviceConfig>().guest_additions;
    }

    void OnReady() override {
        emu_.Get<PeripheralDispatcher>().Register(this);
    }

    uint32_t MmioBase() const override {
        return emu_.Get<BoardContext>().GuestAdditionsWindowBase() +
               CerfVirt::kTickProfilerOffset;
    }
    uint32_t MmioSize() const override { return CerfVirt::kTickProfilerSize; }

    uint32_t ReadWord(uint32_t addr) override {
        const uint32_t off = addr - MmioBase();
        if (off == CerfVirt::kTickProfEnable)
            return emu_.Get<DeviceConfig>().ga_tick_profiler ? 1u : 0u;
        if (off == CerfVirt::kTickProfHostMs) {
            return static_cast<uint32_t>(
                emu_.Get<VirtualClock>().NowNs() / 1000000ll);
        }
        HaltUnsupportedAccess("ReadWord", addr, 0);
    }
};

REGISTER_SERVICE(CerfVirtTickProfiler);

}
