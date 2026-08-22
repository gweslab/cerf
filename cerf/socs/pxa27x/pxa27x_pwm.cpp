#include "../../peripherals/peripheral_base.h"

#include "../../boards/board_context.h"
#include "../../core/cerf_emulator.h"
#include "../../peripherals/peripheral_dispatcher.h"
#include "../../state/state_stream.h"

#include <cstdint>

namespace {

/* Intel PXA27x Developer's Manual 280000-001 Table 23-5 (page 23-10) "PWM
   Control Registers": 0x40B0_0000 PWMCR0 / 0004 PWMDCR0 / 0008 PWMPCR0 /
   000C reserved / 0010 PWMCR2 / 0014 PWMDCR2 / 0018 PWMPCR2, and the same
   layout at 0x40C0_0000 for PWMCR1/PWMDCR1/PWMPCR1/PWMCR3/PWMDCR3/PWMPCR3. */
class Pxa27xPwm : public Peripheral {
public:
    using Peripheral::Peripheral;

    bool ShouldRegister() override {
        auto* bd = emu_.TryGet<BoardContext>();
        return bd && bd->GetSoc() == SocFamily::PXA27x;
    }
    void OnReady() override {
        emu_.Get<PeripheralDispatcher>().Register(this);
    }

    uint32_t MmioSize() const override { return 0x00001000u; }

    uint32_t ReadWord(uint32_t addr) override {
        const uint32_t off = addr - MmioBase();
        if (IsRegister(off)) return regs_[off / 4u];
        HaltUnsupportedAccess("ReadWord", addr, 0);
    }

    void WriteWord(uint32_t addr, uint32_t value) override {
        const uint32_t off = addr - MmioBase();
        if (IsRegister(off)) { regs_[off / 4u] = value & MaskOf(off); return; }
        HaltUnsupportedAccess("WriteWord", addr, value);
    }

    void SaveState(StateWriter& w) override { w.WriteBytes(regs_, sizeof(regs_)); }
    void RestoreState(StateReader& r) override { r.ReadBytes(regs_, sizeof(regs_)); }

private:
    enum : uint32_t {
        kCrA = 0x00, kDcrA = 0x04, kPcrA = 0x08,
        kCrB = 0x10, kDcrB = 0x14, kPcrB = 0x18,
    };

    static bool IsRegister(uint32_t off) {
        switch (off) {
        case kCrA: case kDcrA: case kPcrA:
        case kCrB: case kDcrB: case kPcrB:
            return true;
        default:
            return false;
        }
    }

    /* Table 23-2 (page 23-7) "31:7 reserved / 6 SD / 5:0 PRESCALE"; Table 23-3
       (page 23-8) "31:11 reserved / 10 FD / 9:0 DCYCLE"; Table 23-4 (page 23-9)
       "31:10 reserved / 9:0 PV". */
    static uint32_t MaskOf(uint32_t off) {
        switch (off) {
        case kCrA:  case kCrB:  return 0x0000007Fu;
        case kDcrA: case kDcrB: return 0x000007FFu;
        default:                return 0x000003FFu;
        }
    }

    /* Table 23-4 (page 23-9) PWMPCR reset row "... 0 0 0 0 0 0 0 1 0 0"; the
       Table 23-2 and Table 23-3 reset rows are all zeros. */
    uint32_t regs_[(kPcrB / 4u) + 1u] = {
        0u, 0u, 0x00000004u, 0u, 0u, 0u, 0x00000004u,
    };
};

/* Table 23-5 (page 23-10): "0x40B0_0000 PWMCR0", "0x40B0_0010 PWMCR2". */
class Pxa27xPwm02 : public Pxa27xPwm {
public:
    using Pxa27xPwm::Pxa27xPwm;

    uint32_t MmioBase() const override { return 0x40B00000u; }
};

/* Table 23-5 (page 23-10): "0x40C0_0000 PWMCR1", "0x40C0_0010 PWMCR3". */
class Pxa27xPwm13 : public Pxa27xPwm {
public:
    using Pxa27xPwm::Pxa27xPwm;

    uint32_t MmioBase() const override { return 0x40C00000u; }
};

}  /* namespace */

REGISTER_SERVICE(Pxa27xPwm02);
REGISTER_SERVICE(Pxa27xPwm13);
