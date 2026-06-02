#include "../../peripherals/peripheral_base.h"

#include "../../core/cerf_emulator.h"
#include "../../boards/board_detector.h"
#include "../../peripherals/peripheral_dispatcher.h"

#include <cstdint>

namespace {

constexpr uint32_t kAipsRegionSize  = 0x00001000u;
constexpr uint32_t kPacrReset       = 0x44444444u;

class Imx31AipsBase : public Peripheral {
public:
    using Peripheral::Peripheral;

    uint32_t MmioSize() const override { return kAipsRegionSize; }
    uint32_t ReadWord (uint32_t addr) override;
    void     WriteWord(uint32_t addr, uint32_t value) override;

protected:
    uint32_t regs_[11] = {
        0u, 0u,
        kPacrReset, kPacrReset, kPacrReset, kPacrReset,
        kPacrReset, kPacrReset, kPacrReset, kPacrReset, kPacrReset,
    };

    static bool OffsetToIndex(uint32_t off, uint32_t* index_out) {
        if      (off == 0x00) { *index_out = 0; return true; }
        else if (off == 0x04) { *index_out = 1; return true; }
        else if (off >= 0x20 && off <= 0x2C && (off & 0x3u) == 0) {
            *index_out = 2u + (off - 0x20u) / 4u;
            return true;
        }
        else if (off >= 0x40 && off <= 0x50 && (off & 0x3u) == 0) {
            *index_out = 6u + (off - 0x40u) / 4u;
            return true;
        }
        return false;
    }
};

uint32_t Imx31AipsBase::ReadWord(uint32_t addr) {
    const uint32_t off = addr - MmioBase();
    uint32_t idx;
    if (!OffsetToIndex(off, &idx)) HaltUnsupportedAccess("ReadWord", addr, 0);
    return regs_[idx];
}

void Imx31AipsBase::WriteWord(uint32_t addr, uint32_t value) {
    const uint32_t off = addr - MmioBase();
    uint32_t idx;
    if (!OffsetToIndex(off, &idx)) HaltUnsupportedAccess("WriteWord", addr, value);
    regs_[idx] = value;
}

class Imx31AipsA : public Imx31AipsBase {
public:
    using Imx31AipsBase::Imx31AipsBase;
    bool ShouldRegister() override {
        auto* bd = emu_.TryGet<BoardDetector>();
        return bd && bd->GetSoc() == SocFamily::iMX31;
    }
    void OnReady() override {
        emu_.Get<PeripheralDispatcher>().Register(this);
    }
    uint32_t MmioBase() const override { return 0x43F00000u; }
};

class Imx31AipsB : public Imx31AipsBase {
public:
    using Imx31AipsBase::Imx31AipsBase;
    bool ShouldRegister() override {
        auto* bd = emu_.TryGet<BoardDetector>();
        return bd && bd->GetSoc() == SocFamily::iMX31;
    }
    void OnReady() override {
        emu_.Get<PeripheralDispatcher>().Register(this);
    }
    uint32_t MmioBase() const override { return 0x53F00000u; }
};

}  /* namespace */

REGISTER_SERVICE(Imx31AipsA);
REGISTER_SERVICE(Imx31AipsB);
