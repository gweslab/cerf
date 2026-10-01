#include "../../peripherals/peripheral_base.h"

#include "../../core/cerf_emulator.h"
#include "../../boards/board_context.h"
#include "imx51_id.h"
#include "../../peripherals/peripheral_dispatcher.h"
#include "../freescale_module_clocks.h"

#include <cstdint>

namespace {

/* i.MX51 boot ROM (PA 0x0): the OAL reads the silicon rev at 0x48, MMU off
   (nk.exe start `v6=MEMORY[0x48]`). v6>=16 programs TZIC at 0xE0000000; v6<16
   targets 0x90000000 and interrupts never arrive. >=32 = latest silicon, so
   this Elvis-TO3 unit needs >=32. */
constexpr uint32_t kBase        = 0x00000000u;
constexpr uint32_t kSize        = 0x00001000u;
constexpr uint32_t kSiRevOff    = 0x48u;
constexpr uint32_t kSiRevTo3    = 0x20u;   /* >=32: Elvis TO3 path (TZIC + latest silicon) */

class Imx51BootRom : public Peripheral {
public:
    using Peripheral::Peripheral;

    bool ShouldRegister() override {
        auto* bd = emu_.TryGet<BoardContext>();
        return bd && bd->GetSocId() == SocId::Imx51;
    }
    void OnReady() override {
        module_clocks_ = &emu_.Get<FreescaleModuleClocks>();
        emu_.Get<PeripheralDispatcher>().Register(this);
    }

    uint32_t MmioBase() const override { return kBase; }
    uint32_t MmioSize() const override { return kSize; }

    uint32_t ReadWord(uint32_t addr) override {
        if (addr - kBase == kSiRevOff) {
            module_clocks_->RequireRunning(FreescaleModule::kRom, "is read");
            return kSiRevTo3;
        }
        HaltUnsupportedAccess("ReadWord", addr, 0);
    }

    void WriteWord(uint32_t addr, uint32_t value) override {
        HaltUnsupportedAccess("WriteWord", addr, value);  /* mask ROM: read-only */
    }

private:
    FreescaleModuleClocks* module_clocks_ = nullptr;
};

}  /* namespace */

REGISTER_SERVICE(Imx51BootRom);
