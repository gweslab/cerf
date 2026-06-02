#include "../../peripherals/peripheral_base.h"

#include "../../core/cerf_emulator.h"
#include "../../boards/board_detector.h"
#include "../../peripherals/peripheral_dispatcher.h"

#include <cstdint>

namespace {

constexpr uint32_t kM3ifBase = 0xB8003000u;
constexpr uint32_t kM3ifSize = 0x00001000u;

class Imx31M3if : public Peripheral {
public:
    using Peripheral::Peripheral;

    bool ShouldRegister() override {
        auto* bd = emu_.TryGet<BoardDetector>();
        return bd && bd->GetSoc() == SocFamily::iMX31;
    }
    void OnReady() override {
        emu_.Get<PeripheralDispatcher>().Register(this);
    }

    uint32_t MmioBase() const override { return kM3ifBase; }
    uint32_t MmioSize() const override { return kM3ifSize; }

    uint32_t ReadWord (uint32_t addr) override;
    void     WriteWord(uint32_t addr, uint32_t value) override;

private:
    uint32_t regs_[12] = {};

    static bool OffsetToIndex(uint32_t off, uint32_t* index_out) {
        if (off == 0x000) { *index_out =  0; return true; }
        if (off >= 0x028 && off <= 0x030 && (off & 0x3u) == 0) {
            *index_out = 1u + (off - 0x028u) / 4u;
            return true;
        }
        if (off >= 0x034 && off <= 0x038 && (off & 0x3u) == 0) {
            *index_out = 4u + (off - 0x034u) / 4u;
            return true;
        }
        if (off >= 0x040 && off <= 0x054 && (off & 0x3u) == 0) {
            *index_out = 6u + (off - 0x040u) / 4u;
            return true;
        }
        return false;
    }
};

uint32_t Imx31M3if::ReadWord(uint32_t addr) {
    const uint32_t off = addr - MmioBase();
    uint32_t idx;
    if (!OffsetToIndex(off, &idx)) HaltUnsupportedAccess("ReadWord", addr, 0);
    return regs_[idx];
}

void Imx31M3if::WriteWord(uint32_t addr, uint32_t value) {
    const uint32_t off = addr - MmioBase();
    uint32_t idx;
    if (!OffsetToIndex(off, &idx)) HaltUnsupportedAccess("WriteWord", addr, value);
    regs_[idx] = value;
}

}  /* namespace */

REGISTER_SERVICE(Imx31M3if);
