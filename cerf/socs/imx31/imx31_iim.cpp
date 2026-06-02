#include "../../peripherals/peripheral_base.h"

#include "../../core/cerf_emulator.h"
#include "../../core/log.h"
#include "../../boards/board_detector.h"
#include "../../peripherals/peripheral_dispatcher.h"

#include <cstdint>

namespace {

constexpr uint32_t kBase = 0x5001C000u;
constexpr uint32_t kSize = 0x00004000u;

constexpr uint32_t kOffStat   = 0x00u;
constexpr uint32_t kOffStatm  = 0x04u;
constexpr uint32_t kOffErr    = 0x08u;
constexpr uint32_t kOffEmask  = 0x0Cu;
constexpr uint32_t kOffFctl   = 0x10u;
constexpr uint32_t kOffUa     = 0x14u;
constexpr uint32_t kOffLa     = 0x18u;
constexpr uint32_t kOffSdat   = 0x1Cu;
constexpr uint32_t kOffPrev   = 0x20u;
constexpr uint32_t kOffSrev   = 0x24u;
constexpr uint32_t kOffPrgP   = 0x28u;

/* U-Boot mainline iim_regs: bank 2 at +0x1000, 0x400 bytes. Kernel
   sub_88244F10 (IDA 0x88244F60) reads 7 bytes within. */
constexpr uint32_t kFuseBank2Start = 0x1000u;
constexpr uint32_t kFuseBank2End   = 0x1400u;

/* MCIMX31RM Table 13-2: SREV=0x14 = i.MX31 silicon rev 1.2 (M45G mask),
   the production silicon shipping when the Zune 30 launched (2006-09). */
constexpr uint32_t kSrevImx31Rev12 = 0x14u;

class Imx31Iim : public Peripheral {
public:
    using Peripheral::Peripheral;

    bool ShouldRegister() override {
        auto* bd = emu_.TryGet<BoardDetector>();
        return bd && bd->GetSoc() == SocFamily::iMX31;
    }
    void OnReady() override {
        emu_.Get<PeripheralDispatcher>().Register(this);
    }

    uint32_t MmioBase() const override { return kBase; }
    uint32_t MmioSize() const override { return kSize; }

    uint32_t ReadWord(uint32_t addr) override {
        const uint32_t off = addr - kBase;
        switch (off) {
            case kOffSrev: return kSrevImx31Rev12;
        }
        if (off >= kFuseBank2Start && off < kFuseBank2End) {
            LOG(Periph, "[IIM] bank2 word off=0x%04X = 0 (unblown)\n", off);
            return 0;
        }
        HaltUnsupportedAccess("ReadWord", addr, 0);
    }

    uint8_t ReadByte(uint32_t addr) override {
        const uint32_t off = addr - kBase;
        /* Bank 2 unblown e-fuses read 0 (Table 13-1 'Setting' column). */
        if (off >= kFuseBank2Start && off < kFuseBank2End) {
            LOG(Periph, "[IIM] bank2 byte off=0x%04X = 0 (unblown)\n", off);
            return 0;
        }
        HaltUnsupportedAccess("ReadByte", addr, 0);
    }

    void WriteWord(uint32_t addr, uint32_t value) override {
        HaltUnsupportedAccess("WriteWord", addr, value);
    }
};

}  /* namespace */

REGISTER_SERVICE(Imx31Iim);
