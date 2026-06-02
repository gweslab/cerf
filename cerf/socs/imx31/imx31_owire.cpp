#include "../../peripherals/peripheral_base.h"

#include "../../core/cerf_emulator.h"
#include "../../boards/board_detector.h"
#include "../../peripherals/peripheral_dispatcher.h"

#include <cstdint>

namespace {

/* i.MX31 1-Wire (OWIRE) — MCIMX31RM Ch 22 @0x43F9_C000. CONTROL's RPP/WR0/WR1
   are self-clearing strobes (Table 22-4): they must read back 0 or the driver's
   poll-until-clear loop wedges. No device -> PST(6)=0; a read samples idle-high
   -> RDST(3)=1. */
constexpr uint32_t kBase = 0x43F9C000u;
constexpr uint32_t kSize = 0x00000008u;  /* CONTROL/TIME_DIVIDER/RESET (Table 22-1) */

constexpr uint32_t kControl     = 0x00u;
constexpr uint32_t kTimeDivider = 0x02u;
constexpr uint32_t kReset       = 0x04u;

constexpr uint16_t kCtrlRpp  = 1u << 7;  /* Reset/Presence Pulse, self-clearing (Table 22-4) */
constexpr uint16_t kCtrlWr0  = 1u << 5;  /* Write 0 bit, self-clearing */
constexpr uint16_t kCtrlWr1  = 1u << 4;  /* Write 1 / Read, self-clearing */
constexpr uint16_t kCtrlRdst = 1u << 3;  /* Read-bit result (1 = sampled high) */

class Imx31Owire : public Peripheral {
public:
    using Peripheral::Peripheral;

    bool ShouldRegister() override {
        auto* bd = emu_.TryGet<BoardDetector>();
        return bd && bd->GetSoc() == SocFamily::iMX31;
    }
    void OnReady() override { emu_.Get<PeripheralDispatcher>().Register(this); }

    uint32_t MmioBase() const override { return kBase; }
    uint32_t MmioSize() const override { return kSize; }

    uint16_t ReadHalf(uint32_t addr) override { return ReadReg16(addr - kBase); }
    void WriteHalf(uint32_t addr, uint16_t value) override {
        WriteReg16(addr - kBase, value);
    }
    uint8_t ReadByte(uint32_t addr) override {
        const uint16_t v = ReadReg16((addr - kBase) & ~1u);
        return ((addr & 1u) ? (v >> 8) : v) & 0xFFu;
    }
    void WriteByte(uint32_t addr, uint8_t value) override {
        const uint32_t off = (addr - kBase) & ~1u;
        uint16_t v = ReadReg16(off);
        v = (addr & 1u) ? ((v & 0x00FFu) | (uint16_t(value) << 8))
                        : ((v & 0xFF00u) | value);
        WriteReg16(off, v);
    }

private:
    uint16_t ReadReg16(uint32_t off) {
        switch (off) {
            /* RPP/WR0/WR1 self-cleared (read 0); PST=0 (no device); RDST per
               the last read (no device -> idle-high -> 1). */
            case kControl:     return control_;
            case kTimeDivider: return time_divider_;
            case kReset:       return reset_;
        }
        HaltUnsupportedAccess("ReadReg16", kBase + off, 0);
    }
    void WriteReg16(uint32_t off, uint16_t value) {
        switch (off) {
            /* No 1-Wire device responds: RPP leaves PST=0; WR1 (read) samples
               the idle-high bus -> RDST=1. The strobe bits self-clear, so none
               persist into control_. */
            case kControl:
                if (value & kCtrlWr1) control_ |= kCtrlRdst;
                return;
            case kTimeDivider: time_divider_ = value; return;
            /* RST=1 holds the module in reset, clearing its registers
               (Table 22-8); release with RST=0. */
            case kReset:
                reset_ = value;
                if (value & 1u) control_ = 0;
                return;
        }
        HaltUnsupportedAccess("WriteReg16", kBase + off, value);
    }

    uint16_t control_      = 0;  /* PST(6)=0 no device; only RDST(3) ever set */
    uint16_t time_divider_ = 0;
    uint16_t reset_        = 0;
};

}  /* namespace */

REGISTER_SERVICE(Imx31Owire);
