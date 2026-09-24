#include "../../peripherals/peripheral_base.h"

#include "../../core/cerf_emulator.h"
#include "../../core/log.h"
#include "../../boards/board_context.h"
#include "s3c2410_id.h"
#include "../../peripherals/peripheral_dispatcher.h"
#include "../../state/state_stream.h"

namespace {

class S3C2410Watchdog : public Peripheral {
public:
    using Peripheral::Peripheral;

    bool ShouldRegister() override {
        auto* bd = emu_.TryGet<BoardContext>();
        return bd && bd->GetSocId() == SocId::S3c2410;
    }
    void OnReady() override {
        emu_.Get<PeripheralDispatcher>().Register(this);
    }

    uint32_t MmioBase() const override { return 0x53000000u; }
    uint32_t MmioSize() const override { return 0x00100000u; }  /* 1 MB section */

    uint32_t ReadWord (uint32_t addr) override;
    void     WriteWord(uint32_t addr, uint32_t value) override;

    /* JIT-thread-only register file (no worker thread) - the JIT is paused
       during save/restore, so no lock is needed. */
    void SaveState(StateWriter& w) override    { w.WriteBytes("storage", storage_, sizeof(storage_)); }
    void RestoreState(StateReader& r) override { r.ReadBytes("storage", storage_, sizeof(storage_)); }

private:
    static constexpr size_t kSlotCount = 3;  /* WTCON / WTDAT / WTCNT */
    uint32_t storage_[kSlotCount] = {};
};

uint32_t S3C2410Watchdog::ReadWord(uint32_t addr) {
    const uint32_t slot = (addr - MmioBase()) / 4u;
    if (slot >= kSlotCount) {
        HaltUnsupportedAccess("ReadWord", addr, 0);
    }
    const uint32_t value = storage_[slot];
    LOG(SocWdt, "read  +0x%02X -> 0x%08X\n",
        addr - MmioBase(), value);
    return value;
}

void S3C2410Watchdog::WriteWord(uint32_t addr, uint32_t value) {
    const uint32_t slot = (addr - MmioBase()) / 4u;
    if (slot >= kSlotCount) {
        HaltUnsupportedAccess("WriteWord", addr, value);
    }
    LOG(SocWdt, "write +0x%02X = 0x%08X\n",
        addr - MmioBase(), value);
    storage_[slot] = value;
}

}  /* namespace */

REGISTER_SERVICE(S3C2410Watchdog);
