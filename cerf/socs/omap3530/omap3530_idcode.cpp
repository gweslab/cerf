#include "../../peripherals/peripheral_base.h"

#include "../../core/cerf_emulator.h"
#include "../../core/log.h"
#include "../../peripherals/peripheral_dispatcher.h"
#include "../../boards/board_detector.h"

#include <cstdint>

namespace {

constexpr uint32_t kIdcodeBasePa = 0x4830A000u;
constexpr uint32_t kIdcodeSize   = 0x00001000u;  /* 4 KB page */

constexpr uint32_t kOffIdcode   = 0x204;
constexpr uint32_t kIdcodeValue = 0x40000000u;  /* ES3.1 in bits[31:28] */

class Omap3530Idcode : public Peripheral {
public:
    using Peripheral::Peripheral;

    bool ShouldRegister() override {
        auto* bd = emu_.TryGet<BoardDetector>();
        return bd && bd->GetSoc() == SocFamily::OMAP3530;
    }
    void OnReady() override {
        emu_.Get<PeripheralDispatcher>().Register(this);
    }

    uint32_t MmioBase() const override { return kIdcodeBasePa; }
    uint32_t MmioSize() const override { return kIdcodeSize; }

    uint32_t ReadWord (uint32_t addr) override;
    void     WriteWord(uint32_t addr, uint32_t value) override;
};

uint32_t Omap3530Idcode::ReadWord(uint32_t addr) {
    const uint32_t off = addr - MmioBase();
    if (off == kOffIdcode) return kIdcodeValue;
    HaltUnsupportedAccess("ReadWord (only IDCODE at 0x204 is modelled)",
                          addr, 0);
}

void Omap3530Idcode::WriteWord(uint32_t addr, uint32_t value) {
    /* IDCODE is a read-only fused silicon register. */
    HaltUnsupportedAccess("WriteWord (IDCODE is read-only)", addr, value);
}

}  /* namespace */

REGISTER_SERVICE(Omap3530Idcode);
