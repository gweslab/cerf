#include "../../peripherals/peripheral_base.h"

#include "../../boards/board_detector.h"
#include "../../core/cerf_emulator.h"
#include "../../core/log.h"
#include "../../peripherals/peripheral_dispatcher.h"

#include <array>
#include <cstdint>
#include <mutex>

namespace {

constexpr uint32_t kBasePa = 0x48002000u;
constexpr uint32_t kSize   = 0x00001000u;

class Omap3530SyscPadconf : public Peripheral {
public:
    using Peripheral::Peripheral;

    bool ShouldRegister() override {
        auto* bd = emu_.TryGet<BoardDetector>();
        return bd && bd->GetSoc() == SocFamily::OMAP3530;
    }
    void OnReady() override {
        emu_.Get<PeripheralDispatcher>().Register(this);
    }

    uint32_t MmioBase() const override { return kBasePa; }
    uint32_t MmioSize() const override { return kSize; }

    uint16_t ReadHalf  (uint32_t addr) override;
    uint32_t ReadWord  (uint32_t addr) override;
    void     WriteHalf (uint32_t addr, uint16_t value) override;
    void     WriteWord (uint32_t addr, uint32_t value) override;

private:
    mutable std::mutex mu_;
    std::array<uint16_t, kSize / 2> regs_{};
};

uint16_t Omap3530SyscPadconf::ReadHalf(uint32_t addr) {
    const uint32_t off = addr - MmioBase();
    if (off & 1u) HaltUnsupportedAccess("ReadHalf (misaligned)", addr, 0);
    std::lock_guard<std::mutex> lk(mu_);
    const uint16_t value = regs_[off / 2];
    LOG(Periph, "[SYSC_PADCONF] R16 0x%03X -> 0x%04X\n", off, value);
    return value;
}

uint32_t Omap3530SyscPadconf::ReadWord(uint32_t addr) {
    const uint32_t off = addr - MmioBase();
    if (off & 3u) HaltUnsupportedAccess("ReadWord (misaligned)", addr, 0);
    std::lock_guard<std::mutex> lk(mu_);
    const uint32_t lo = regs_[off / 2];
    const uint32_t hi = regs_[off / 2 + 1];
    const uint32_t value = lo | (hi << 16);
    LOG(Periph, "[SYSC_PADCONF] R32 0x%03X -> 0x%08X\n", off, value);
    return value;
}

void Omap3530SyscPadconf::WriteHalf(uint32_t addr, uint16_t value) {
    const uint32_t off = addr - MmioBase();
    if (off & 1u) HaltUnsupportedAccess("WriteHalf (misaligned)", addr, value);
    std::lock_guard<std::mutex> lk(mu_);
    LOG(Periph, "[SYSC_PADCONF] W16 0x%03X <- 0x%04X\n", off, value);
    regs_[off / 2] = value;
}

void Omap3530SyscPadconf::WriteWord(uint32_t addr, uint32_t value) {
    const uint32_t off = addr - MmioBase();
    if (off & 3u) HaltUnsupportedAccess("WriteWord (misaligned)", addr, value);
    std::lock_guard<std::mutex> lk(mu_);
    LOG(Periph, "[SYSC_PADCONF] W32 0x%03X <- 0x%08X\n", off, value);
    regs_[off / 2]     = static_cast<uint16_t>(value & 0xFFFFu);
    regs_[off / 2 + 1] = static_cast<uint16_t>(value >> 16);

    /* Without this side-effect, OALContextSaveMux hot-polls
       CONTROL_GENERAL_PURPOSE_STATUS.SAVEDONE forever and boot stalls. */
    constexpr uint32_t kPadconfOffOffset = 0x270u;
    constexpr uint32_t kGpStatusOffset   = 0x2F4u;
    constexpr uint32_t kStartSaveBit     = 1u << 1;
    constexpr uint16_t kSaveDoneBit      = 1u << 0;
    if (off == kPadconfOffOffset && (value & kStartSaveBit)) {
        regs_[kGpStatusOffset / 2] |= kSaveDoneBit;
    }
}

}  /* namespace */

REGISTER_SERVICE(Omap3530SyscPadconf);
