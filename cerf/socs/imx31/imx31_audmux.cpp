#include "../../peripherals/peripheral_base.h"

#include "../../core/cerf_emulator.h"
#include "../../boards/board_detector.h"
#include "../../peripherals/peripheral_dispatcher.h"

#include <array>
#include <cstdint>

namespace {

constexpr uint32_t kBase = 0x53FC4000u;
constexpr uint32_t kSize = 0x00004000u;
constexpr uint32_t kLastOff = 0x38u;

/* Resets per Table 42-2, index = offset/4 (PTCR1,PDCR1,PTCR2,PDCR2,...,CNMCR). */
constexpr std::array<uint32_t, 15> kReset = {
    0xAD400800u, 0x0000A000u, 0xA5000800u, 0x00008000u, 0xC0C00800u,
    0x00006000u, 0x00000800u, 0x00004000u, 0x00000800u, 0x00002000u,
    0x00000800u, 0x00000000u, 0x00000800u, 0x00000000u, 0x00031010u,
};

class Imx31Audmux : public Peripheral {
public:
    using Peripheral::Peripheral;

    bool ShouldRegister() override {
        auto* bd = emu_.TryGet<BoardDetector>();
        return bd && bd->GetSoc() == SocFamily::iMX31;
    }
    void OnReady() override { emu_.Get<PeripheralDispatcher>().Register(this); }

    uint32_t MmioBase() const override { return kBase; }
    uint32_t MmioSize() const override { return kSize; }

    uint32_t ReadWord(uint32_t addr) override {
        const uint32_t off = addr - kBase;
        if (off <= kLastOff && (off & 3u) == 0u) {
            return regs_[off >> 2];
        }
        HaltUnsupportedAccess("ReadWord", addr, 0);
    }

    void WriteWord(uint32_t addr, uint32_t value) override {
        const uint32_t off = addr - kBase;
        if (off <= kLastOff && (off & 3u) == 0u) {
            regs_[off >> 2] = value;
            return;
        }
        HaltUnsupportedAccess("WriteWord", addr, value);
    }

private:
    std::array<uint32_t, 15> regs_ = kReset;
};

}  /* namespace */

REGISTER_SERVICE(Imx31Audmux);
