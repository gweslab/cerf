#include "../../peripherals/peripheral_base.h"

#include "../../core/cerf_emulator.h"
#include "../../boards/board_detector.h"
#include "../../peripherals/peripheral_dispatcher.h"

namespace {

/* PXA255 Power Manager block (manual Table 3-27, base 0x40F00000).
   ACTIVE-mode config registers hold their value; sleep is entered by the
   CP14 PWRMODE write (coproc emitter → WfiHelper), never by a store here.
   RCSR/PSSR/PEDR are write-1-to-clear; RCSR HWR cold-resets to 1 (§3.5.11). */
class Pxa255PowerManager : public Peripheral {
public:
    using Peripheral::Peripheral;

    bool ShouldRegister() override {
        auto* bd = emu_.TryGet<BoardDetector>();
        return bd && bd->GetSoc() == SocFamily::PXA25x;
    }
    void OnReady() override {
        emu_.Get<PeripheralDispatcher>().Register(this);
    }

    uint32_t MmioBase() const override { return 0x40F00000u; }
    uint32_t MmioSize() const override { return 0x00001000u; }

    uint32_t ReadWord (uint32_t addr) override;
    void     WriteWord(uint32_t addr, uint32_t value) override;

private:
    enum : uint32_t {
        kPMCR  = 0x00, kPSSR  = 0x04, kPSPR  = 0x08, kPWER  = 0x0C,
        kPRER  = 0x10, kPFER  = 0x14, kPEDR  = 0x18, kPCFR  = 0x1C,
        kPGSR0 = 0x20, kPGSR1 = 0x24, kPGSR2 = 0x28, kRCSR  = 0x30,
    };

    uint32_t pmcr_ = 0, pspr_ = 0, pedr_ = 0, pcfr_ = 0,
             pgsr0_ = 0, pgsr1_ = 0, pgsr2_ = 0;
    /* Non-zero cold-reset values from the manual register figures:
       PSSR RDH(bit5)=1; PWER/PRER/PFER GPIO-edge enable[1:0]=0x3; RCSR HWR=1. */
    uint32_t pssr_ = 0x20u;  /* §3.5.7  Table 3-13 */
    uint32_t pwer_ = 0x3u;   /* §3.5.3  Table 3-9  */
    uint32_t prer_ = 0x3u;   /* §3.5.4  Table 3-10 */
    uint32_t pfer_ = 0x3u;   /* §3.5.5  Table 3-11 */
    uint32_t rcsr_ = 0x1u;   /* §3.5.11 HWR cold-reset */
};

uint32_t Pxa255PowerManager::ReadWord(uint32_t addr) {
    switch (addr - MmioBase()) {
    case kPMCR:  return pmcr_;
    case kPSSR:  return pssr_;
    case kPSPR:  return pspr_;
    case kPWER:  return pwer_;
    case kPRER:  return prer_;
    case kPFER:  return pfer_;
    case kPEDR:  return pedr_;
    case kPCFR:  return pcfr_;
    case kPGSR0: return pgsr0_;
    case kPGSR1: return pgsr1_;
    case kPGSR2: return pgsr2_;
    case kRCSR:  return rcsr_;
    }
    HaltUnsupportedAccess("ReadWord", addr, 0);
}

void Pxa255PowerManager::WriteWord(uint32_t addr, uint32_t value) {
    switch (addr - MmioBase()) {
    case kPMCR:  pmcr_  = value; return;
    case kPSPR:  pspr_  = value; return;
    case kPWER:  pwer_  = value; return;
    case kPRER:  prer_  = value; return;
    case kPFER:  pfer_  = value; return;
    case kPCFR:  pcfr_  = value; return;
    case kPGSR0: pgsr0_ = value; return;
    case kPGSR1: pgsr1_ = value; return;
    case kPGSR2: pgsr2_ = value; return;
    /* Write-1-to-clear status registers. */
    case kPSSR:  pssr_ &= ~value;        return;
    case kPEDR:  pedr_ &= ~value;        return;
    case kRCSR:  rcsr_ &= ~(value & 0xFu); return;
    }
    HaltUnsupportedAccess("WriteWord", addr, value);
}

}  /* namespace */

REGISTER_SERVICE(Pxa255PowerManager);
