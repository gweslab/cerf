#include "../../peripherals/peripheral_base.h"

#include "../../core/cerf_emulator.h"
#include "../../core/log.h"
#include "../../peripherals/peripheral_dispatcher.h"
#include "../board_detector.h"

#include <cstdint>
#include <mutex>

namespace {

constexpr uint32_t kBase = 0x500F5000u;
constexpr uint32_t kSize = 0x00000008u;

constexpr uint32_t kRegInterruptMask    = 0x00u;
constexpr uint32_t kRegInterruptPending = 0x04u;

class DevEmuEmulServ : public Peripheral {
public:
    using Peripheral::Peripheral;

    bool ShouldRegister() override {
        auto* bd = emu_.TryGet<BoardDetector>();
        return bd && bd->GetBoard() == Board::Smdk2410DevEmu;
    }
    void OnReady() override {
        emu_.Get<PeripheralDispatcher>().Register(this);
    }

    uint32_t MmioBase() const override { return kBase; }
    uint32_t MmioSize() const override { return kSize; }

    uint32_t ReadWord (uint32_t addr) override;
    void     WriteWord(uint32_t addr, uint32_t value) override;

private:
    mutable std::mutex state_mutex_;
    uint32_t           interrupt_mask_    = 0;
    uint32_t           interrupt_pending_ = 0;
};

uint32_t DevEmuEmulServ::ReadWord(uint32_t addr) {
    const uint32_t off = addr - kBase;
    uint32_t value = 0;
    {
        std::lock_guard<std::mutex> lk(state_mutex_);
        switch (off) {
            case kRegInterruptMask:
                value = interrupt_mask_;
                break;
            case kRegInterruptPending:
                value              = interrupt_pending_;
                interrupt_pending_ = 0;
                break;
            default:
                HaltUnsupportedAccess("ReadWord", addr, 0);  /* noreturn */
        }
    }
    LOG(Periph, "[EmulServ] read32 +0x%02X -> 0x%08X (stub)\n", off, value);
    return value;
}

void DevEmuEmulServ::WriteWord(uint32_t addr, uint32_t value) {
    const uint32_t off = addr - kBase;
    LOG(Periph, "[EmulServ] write32 +0x%02X = 0x%08X (stub)\n", off, value);
    std::lock_guard<std::mutex> lk(state_mutex_);
    switch (off) {
        case kRegInterruptMask:
            interrupt_mask_ = value;
            break;
        case kRegInterruptPending:
            /* The InterruptPending register is read-only in the real
               impl. Match that. */
            break;
        default:
            HaltUnsupportedAccess("WriteWord", addr, value);  /* noreturn */
    }
}

}  /* namespace */

REGISTER_SERVICE(DevEmuEmulServ);
