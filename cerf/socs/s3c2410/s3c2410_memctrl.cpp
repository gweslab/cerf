#include "../../peripherals/peripheral_base.h"

#include "../../core/cerf_emulator.h"
#include "../../core/log.h"
#include "../../boards/board_detector.h"
#include "../../peripherals/peripheral_dispatcher.h"

namespace {

class S3C2410MemCtrl : public Peripheral {
public:
    using Peripheral::Peripheral;

    bool ShouldRegister() override {
        auto* bd = emu_.TryGet<BoardDetector>();
        return bd && bd->GetSoc() == SocFamily::S3C2410;
    }
    void OnReady() override {
        emu_.Get<PeripheralDispatcher>().Register(this);
    }

    uint32_t MmioBase() const override { return 0x48000000u; }
    uint32_t MmioSize() const override { return 0x00100000u; }

    uint32_t ReadWord (uint32_t addr) override;
    void     WriteWord(uint32_t addr, uint32_t value) override;

private:
    static constexpr size_t kSlotCount = 13;  /* BWSCON..MRSRB7 */
    uint32_t storage_[kSlotCount] = {};
};

uint32_t S3C2410MemCtrl::ReadWord(uint32_t addr) {
    const uint32_t slot = (addr - MmioBase()) / 4u;
    if (slot >= kSlotCount) {
        HaltUnsupportedAccess("ReadWord", addr, 0);
    }
    const uint32_t value = storage_[slot];
    LOG(SocMemc, "read  +0x%02X -> 0x%08X\n",
        addr - MmioBase(), value);
    return value;
}

void S3C2410MemCtrl::WriteWord(uint32_t addr, uint32_t value) {
    const uint32_t slot = (addr - MmioBase()) / 4u;
    if (slot >= kSlotCount) {
        HaltUnsupportedAccess("WriteWord", addr, value);
    }
    LOG(SocMemc, "write +0x%02X = 0x%08X\n",
        addr - MmioBase(), value);
    storage_[slot] = value;
}

}  /* namespace */

REGISTER_SERVICE(S3C2410MemCtrl);
