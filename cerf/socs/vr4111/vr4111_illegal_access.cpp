#include "vr4111_bus_error.h"

#include "../../boards/board_context.h"
#include "../../core/cerf_emulator.h"
#include "../../core/log.h"
#include "../../peripherals/peripheral_base.h"
#include "../../peripherals/peripheral_dispatcher.h"

#include <atomic>
#include <cstdint>

namespace {

/* VR4111 UM 11.4.6 p284, illegal access notification for 0x09FF FFFF to 0x0400 0000;
   Table 11-7: processor write request -> interrupt exception (Int0), processor read
   request -> bus error caused by SysCmd. */
constexpr uint32_t kBase = 0x04000000u;
constexpr uint32_t kSize = 0x0A000000u - 0x04000000u;

class Vr4111IllegalAccess : public Peripheral {
public:
    using Peripheral::Peripheral;

    bool ShouldRegister() override {
        auto* bd = emu_.TryGet<BoardContext>();
        return bd && bd->GetSoc() == SocFamily::VR4111;
    }

    void OnReady() override { emu_.Get<PeripheralDispatcher>().Register(this); }

    uint32_t MmioBase() const override { return kBase; }
    uint32_t MmioSize() const override { return kSize; }

    void WriteByte (uint32_t addr, uint8_t)  override { Notify(addr); }
    void WriteHalf (uint32_t addr, uint16_t) override { Notify(addr); }
    void WriteWord (uint32_t addr, uint32_t) override { Notify(addr); }
    void WriteDword(uint32_t addr, uint64_t) override { Notify(addr); }

private:
    void Notify(uint32_t addr) {
        if (!logged_.exchange(true, std::memory_order_relaxed)) {
            LOG(Periph, "Vr4111IllegalAccess: write to reserved space pa=0x%08X; "
                        "write dropped / BERRST set / WRBERRINTR raised\n", addr);
        }
        emu_.Get<Vr4111BusError>().NotifyIllegalWrite();
    }

    std::atomic<bool> logged_{false};
};

}

REGISTER_SERVICE(Vr4111IllegalAccess);
