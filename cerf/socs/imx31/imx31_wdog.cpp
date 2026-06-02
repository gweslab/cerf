#include "../../peripherals/peripheral_base.h"

#include "../../core/cerf_emulator.h"
#include "../../boards/board_detector.h"
#include "../../peripherals/peripheral_dispatcher.h"

#include <cstdint>

namespace {

/* i.MX31 Watchdog Timer (WDOG) — MCIMX31RM Ch 37, base PA 0x53FD_C000. Three
   16-bit registers. The kernel loads WCR.WT, sets WDE, then services the dog
   (WSR 0x5555/0xAAAA) every cycle and reads WRSR for the boot reason. */
constexpr uint32_t kBase = 0x53FDC000u;
constexpr uint32_t kSize = 0x00004000u;  /* AIPS 16 KB peripheral slot */

constexpr uint32_t kWcr  = 0x00u;  /* Watchdog Control Register      (Fig 37-3) */
constexpr uint32_t kWsr  = 0x02u;  /* Watchdog Service Register                 */
constexpr uint32_t kWrsr = 0x04u;  /* Watchdog Reset Status Register (Table 37-8) */

constexpr uint16_t kWcrReset = 0x0030u;  /* WDA(5) | SRS(4) (Table 37-3) */
constexpr uint16_t kWrsrPwr  = 0x0010u;  /* PWR: reset was power-on (Table 37-8) */

class Imx31Wdog : public Peripheral {
public:
    using Peripheral::Peripheral;

    bool ShouldRegister() override {
        auto* bd = emu_.TryGet<BoardDetector>();
        return bd && bd->GetSoc() == SocFamily::iMX31;
    }
    void OnReady() override { emu_.Get<PeripheralDispatcher>().Register(this); }

    uint32_t MmioBase() const override { return kBase; }
    uint32_t MmioSize() const override { return kSize; }

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

    uint16_t ReadHalf(uint32_t addr) override { return ReadReg16(addr - kBase); }
    void WriteHalf(uint32_t addr, uint16_t value) override {
        WriteReg16(addr - kBase, value);
    }

    uint32_t ReadWord(uint32_t addr) override {
        const uint32_t off = addr - kBase;
        return ReadReg16(off) | (uint32_t(ReadReg16(off + 2)) << 16);
    }
    void WriteWord(uint32_t addr, uint32_t value) override {
        const uint32_t off = addr - kBase;
        WriteReg16(off, value & 0xFFFFu);
        WriteReg16(off + 2, value >> 16);
    }

private:
    uint16_t ReadReg16(uint32_t off) {
        switch (off) {
            case kWcr:  return wcr_;
            case kWsr:  return wsr_;
            case kWrsr: return kWrsrPwr;  /* cold power-on; R/O */
        }
        HaltUnsupportedAccess("ReadReg16", kBase + off, 0);
    }
    void WriteReg16(uint32_t off, uint16_t value) {
        switch (off) {
            case kWcr:  wcr_ = value; return;
            /* DO NOT add a time-out->reset timer here: the kernel services the
               dog (WSR 0x5555/0xAAAA) every cycle so a real watchdog never
               bites, and a SetResetPending timer would only fire a spurious
               mid-boot reset on host/guest timing skew. */
            case kWsr:  wsr_ = value; return;
            case kWrsr: return;  /* read-only (§37.5.4: write raises bus error) */
        }
        HaltUnsupportedAccess("WriteReg16", kBase + off, value);
    }

    uint16_t wcr_ = kWcrReset;
    uint16_t wsr_ = 0;
};

}  /* namespace */

REGISTER_SERVICE(Imx31Wdog);
