#include "../../peripherals/peripheral_base.h"

#include "../../core/cerf_emulator.h"
#include "../../boards/board_context.h"
#include "../../peripherals/peripheral_dispatcher.h"
#include "../../state/state_stream.h"

#include <cstdint>

namespace {

/* Intel PXA27x Developer's Manual 280000-001 chapter 3: Table 3-31 (page 3-95)
   "0x4130_0000 CCCR", Table 3-32 (page 3-97) "0x4130_0004 CKEN", Table 3-34
   (page 3-99) "0x4130_0008 OSCC", Table 3-35 (page 3-101) "0x4130_000C CCSR". */
class Pxa27xClockManager : public Peripheral {
public:
    using Peripheral::Peripheral;

    bool ShouldRegister() override {
        auto* bd = emu_.TryGet<BoardContext>();
        return bd && bd->GetSoc() == SocFamily::PXA27x;
    }
    void OnReady() override {
        emu_.Get<PeripheralDispatcher>().Register(this);
    }

    uint32_t MmioBase() const override { return 0x41300000u; }
    uint32_t MmioSize() const override { return 0x00001000u; }

    uint32_t ReadWord (uint32_t addr) override;
    void     WriteWord(uint32_t addr, uint32_t value) override;

    void SaveState(StateWriter& w) override;
    void RestoreState(StateReader& r) override;

private:
    /* Table 3-31 (pages 3-95, 3-96): "31 R/W CPDIS", "30 R/W PPDIS", "29:28
       reserved", "27 R/W LCD_26", "26 R/W PLL_EARLY_EN", "25 R/W A", "24:11
       reserved", "10:7 R/W 2N", "6:5 reserved", "4:0 R/W L". */
    static constexpr uint32_t kCccrMask = 0xCE00079Fu;

    /* Table 3-32 (page 3-97): "31 R/W CKEN[31]", "30:25 reserved", "24:0 R/W
       CKEN[n] Clock Enable"; the Reset row reads 1 for every non-reserved bit. */
    static constexpr uint32_t kCkenMask = 0x81FFFFFFu;

    /* Table 3-34 (pages 3-99, 3-100): "6:5 R/W OSD", "4 R CRI", "3 R/W PIO_EN",
       "2 R/W TOUT_EN", "1 R/W OON", "0 R OOK". */
    static constexpr uint32_t kOsccMask = 0x0000006Eu;
    static constexpr uint32_t kOsccOon  = 0x00000002u;
    static constexpr uint32_t kOsccOok  = 0x00000001u;

    /* Section 3.8.2.4 (page 3-100): CCSR "bits map functionally to the
       corresponding bits in the Core Clock Configuration register (CCCR), with
       the addition of two bits, CPLCK and PPLCK". Table 3-35 (page 3-101):
       "31 R CPDIS_S", "30 R PPDIS_S", "9:7 R 2N_S", "4:0 R L_S". */
    static constexpr uint32_t kCcsrFromCccr = 0xC000039Fu;

    /* Table 3-35 (page 3-101): "29 R CPLCK ... 1 = Core PLL is locked and ready
       to use", "28 R PPLCK ... Peripheral PLL Lock". */
    static constexpr uint32_t kCcsrLocked = 0x30000000u;

    /* Table 3-31 (page 3-96): 2N "(Reset value 0b010 for N = 1)", L "(Reset
       value 0b00111 for L=7)". */
    uint32_t cccr_ = 0x00000107u;
    uint32_t cken_ = 0x81FFFFFFu;
    /* Section 3.8.2.3 (page 3-98): "If CRI is clear ... OON and TOUT_EN is
       cleared out of power-on or hardware reset." */
    uint32_t oscc_ = 0x00000000u;
};

uint32_t Pxa27xClockManager::ReadWord(uint32_t addr) {
    switch (addr - MmioBase()) {
        case 0x00: return cccr_;
        case 0x04: return cken_;
        /* Section 3.8.2.3 (page 3-99): "32.768-kHz Timekeeping Oscillator OK
           (OOK) sets 2-3 seconds after OON is set". */
        case 0x08: return oscc_ | ((oscc_ & kOsccOon) ? kOsccOok : 0u);
        case 0x0C: return (cccr_ & kCcsrFromCccr) | kCcsrLocked;
    }
    HaltUnsupportedAccess("ReadWord", addr, 0);
}

void Pxa27xClockManager::WriteWord(uint32_t addr, uint32_t value) {
    switch (addr - MmioBase()) {
        case 0x00: cccr_ = value & kCccrMask; return;
        case 0x04: cken_ = value & kCkenMask; return;
        /* Section 3.8.2.3 (page 3-99): "OON can be set only by software and
           cleared only by power-on or hardware reset." */
        case 0x08: oscc_ = (value & kOsccMask) | (oscc_ & kOsccOon); return;
        /* Section 3.8.2.4 (page 3-100): "This is a read-only register." */
        case 0x0C: return;
    }
    HaltUnsupportedAccess("WriteWord", addr, value);
}

void Pxa27xClockManager::SaveState(StateWriter& w) {
    w.Write(cccr_); w.Write(cken_); w.Write(oscc_);
}

void Pxa27xClockManager::RestoreState(StateReader& r) {
    r.Read(cccr_); r.Read(cken_); r.Read(oscc_);
}

}  /* namespace */

REGISTER_SERVICE(Pxa27xClockManager);
