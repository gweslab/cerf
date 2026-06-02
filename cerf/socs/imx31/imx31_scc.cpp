#include "../../peripherals/peripheral_base.h"

#include "../../core/cerf_emulator.h"
#include "../../boards/board_detector.h"
#include "../../peripherals/peripheral_dispatcher.h"

#include <cstdint>

namespace {

/* SCC (Security Controller); no public register map, behavior from keyvault.dll.
   config[0x1C] MUST read invalid (no device-fused key in CERF): keyvault
   sub_2FD48F4 then declines and KEY_Init fails gracefully. A passing config
   lets init reach sub_2FD4538 whose fused-key crypto fails => anti-tamper halt. */
constexpr uint32_t kBase = 0x53FAC000u;
constexpr uint32_t kSize = 0x00004000u;

constexpr uint32_t kCfgOff          = 0x1Cu;
constexpr uint32_t kMonStatusOff    = 0x1000u;
constexpr uint32_t kCipherStatusOff = 0x10u;

class Imx31Scc : public Peripheral {
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
        if (off == kCfgOff)          return 0u;  /* invalid => sub_2FD48F4 declines */
        if (off == kMonStatusOff)    return 0u;
        if (off == kCipherStatusOff) return 0u;
        HaltUnsupportedAccess("ReadWord", addr, 0);
    }
    void WriteWord(uint32_t addr, uint32_t value) override {
        HaltUnsupportedAccess("WriteWord", addr, value);
    }
};

}  /* namespace */

REGISTER_SERVICE(Imx31Scc);
