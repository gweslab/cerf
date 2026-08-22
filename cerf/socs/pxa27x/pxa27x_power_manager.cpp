#include "../../peripherals/peripheral_base.h"

#include "../../core/cerf_emulator.h"
#include "../../boards/board_context.h"
#include "../../host/guest_deep_sleep.h"
#include "../../peripherals/peripheral_dispatcher.h"
#include "../../state/state_stream.h"

namespace {

/* Intel PXA27x Developer's Manual 280000-001 Table 3-38 (page 3-104) "Power
   Manager Register Summary": 0x40F0_0000..0x40F0_00FC. */
class Pxa27xPowerManager : public Peripheral, public DeepSleepWaker {
public:
    using Peripheral::Peripheral;

    bool ShouldRegister() override {
        auto* bd = emu_.TryGet<BoardContext>();
        return bd && bd->GetSoc() == SocFamily::PXA27x;
    }
    void OnReady() override {
        emu_.Get<PeripheralDispatcher>().Register(this);
        emu_.Get<GuestDeepSleep>().RegisterWaker(this);
    }

    /* Table 3-23 RCSR bit 2 SMR "Sleep-Exit Reset from Sleep or Deep-Sleep
       Mode". */
    void LatchSleepWakeCause() override { rcsr_ |= 0x4u; }
    void ClearSleepWakeCause() override { rcsr_ &= ~0x4u; }

    uint32_t MmioBase() const override { return 0x40F00000u; }
    uint32_t MmioSize() const override { return 0x00000100u; }

    uint32_t ReadWord (uint32_t addr) override;
    void     WriteWord(uint32_t addr, uint32_t value) override;

    void SaveState(StateWriter& w) override;
    void RestoreState(StateReader& r) override;

private:
    /* Offsets from Table 3-38. */
    enum : uint32_t {
        kPMCR  = 0x00, kPSSR  = 0x04, kPSPR = 0x08, kPWER = 0x0C,
        kPRER  = 0x10, kPFER  = 0x14, kPEDR = 0x18, kPCFR = 0x1C,
        kPGSR0 = 0x20, kPGSR3 = 0x2C, kRCSR = 0x30, kPSLR = 0x34,
        kPSTR  = 0x38, kPVCR  = 0x40, kPUCR = 0x4C, kPKWR = 0x50,
        kPKSR  = 0x54, kPCMD0 = 0x80, kPCMD31 = 0xFC,
    };

    /* Table 3-13: PMCR bits 5 INTRS, 3 VIDAS, 1 BIDAS carry "Write 0b1 to this
       bit to clear it"; bits 4 IAS, 2 VIDAE, 0 BIDAE are plain read/write. */
    static constexpr uint32_t kPmcrStatus = (1u << 5) | (1u << 3) | (1u << 1);
    /* Table 3-15 PSSR bits 6:0, Table 3-23 RCSR bits 3:0 and Table 3-29 PKSR
       bits 19:0 are R/WC. Table 3-20 PEDR: "These bits are cleared by writing
       0b1 to them. Writing 0b0 to any status bit has no effect." */
    static constexpr uint32_t kPssrW1C = 0x7Fu;
    static constexpr uint32_t kRcsrW1C = 0xFu;
    static constexpr uint32_t kPksrW1C = 0xFFFFFu;

    uint32_t pmcr_ = 0, pspr_ = 0, pedr_ = 0, pcfr_ = 0, pstr_ = 0,
             pvcr_ = 0, pucr_ = 0, pkwr_ = 0, pksr_ = 0;
    /* Table 3-23 Reset row note 1: power-on reset clears GPR/SMR/WDR/HWR. */
    uint32_t rcsr_ = 0;
    uint32_t pgsr_[4]  = {};  /* Table 3-22 PGSR0/1/2/3, reset 0 */
    uint32_t pcmd_[32] = {};  /* Table 3-30 PCMD0-PCMD31, reset 0 */
    /* Non-zero cold-reset values from each register figure's Reset row. */
    uint32_t pssr_ = 0x20u;        /* Table 3-15 RDH=1 */
    uint32_t pwer_ = 0x3u;         /* Table 3-17 */
    uint32_t prer_ = 0x3u;         /* Table 3-18 */
    uint32_t pfer_ = 0x3u;         /* Table 3-19 */
    uint32_t pslr_ = 0xCC000000u;  /* Table 3-24 SYS_DEL=0xC, PWR_DEL=0xC */
};

uint32_t Pxa27xPowerManager::ReadWord(uint32_t addr) {
    const uint32_t off = addr - MmioBase();
    if (off >= kPCMD0 && off <= kPCMD31) return pcmd_[(off - kPCMD0) / 4];
    if (off >= kPGSR0 && off <= kPGSR3)  return pgsr_[(off - kPGSR0) / 4];
    switch (off) {
    case kPMCR: return pmcr_;
    case kPSSR: return pssr_;
    case kPSPR: return pspr_;
    case kPWER: return pwer_;
    case kPRER: return prer_;
    case kPFER: return pfer_;
    case kPEDR: return pedr_;
    case kPCFR: return pcfr_;
    case kRCSR: return rcsr_;
    case kPSLR: return pslr_;
    case kPSTR: return pstr_;
    case kPVCR: return pvcr_;
    case kPUCR: return pucr_;
    case kPKWR: return pkwr_;
    case kPKSR: return pksr_;
    }
    HaltUnsupportedAccess("ReadWord", addr, 0);
}

void Pxa27xPowerManager::WriteWord(uint32_t addr, uint32_t value) {
    const uint32_t off = addr - MmioBase();
    if (off >= kPCMD0 && off <= kPCMD31) {
        pcmd_[(off - kPCMD0) / 4] = value;
        return;
    }
    if (off >= kPGSR0 && off <= kPGSR3) {
        pgsr_[(off - kPGSR0) / 4] = value;
        return;
    }
    switch (off) {
    case kPSPR: pspr_ = value; return;
    case kPWER: pwer_ = value; return;
    case kPRER: prer_ = value; return;
    case kPFER: pfer_ = value; return;
    case kPCFR: pcfr_ = value; return;
    case kPSLR: pslr_ = value; return;
    case kPSTR: pstr_ = value; return;
    case kPVCR: pvcr_ = value; return;
    case kPUCR: pucr_ = value; return;
    case kPKWR: pkwr_ = value; return;
    case kPMCR:
        pmcr_ = (pmcr_ & kPmcrStatus & ~value) | (value & ~kPmcrStatus);
        return;
    case kPSSR: pssr_ &= ~(value & kPssrW1C); return;
    case kPEDR: pedr_ &= ~value;              return;
    case kRCSR: rcsr_ &= ~(value & kRcsrW1C); return;
    case kPKSR: pksr_ &= ~(value & kPksrW1C); return;
    }
    HaltUnsupportedAccess("WriteWord", addr, value);
}

void Pxa27xPowerManager::SaveState(StateWriter& w) {
    w.Write(pmcr_); w.Write(pssr_); w.Write(pspr_); w.Write(pwer_);
    w.Write(prer_); w.Write(pfer_); w.Write(pedr_); w.Write(pcfr_);
    w.Write(rcsr_); w.Write(pslr_); w.Write(pstr_); w.Write(pvcr_);
    w.Write(pucr_); w.Write(pkwr_); w.Write(pksr_);
    for (uint32_t& v : pgsr_) w.Write(v);
    for (uint32_t& v : pcmd_) w.Write(v);
}

void Pxa27xPowerManager::RestoreState(StateReader& r) {
    r.Read(pmcr_); r.Read(pssr_); r.Read(pspr_); r.Read(pwer_);
    r.Read(prer_); r.Read(pfer_); r.Read(pedr_); r.Read(pcfr_);
    r.Read(rcsr_); r.Read(pslr_); r.Read(pstr_); r.Read(pvcr_);
    r.Read(pucr_); r.Read(pkwr_); r.Read(pksr_);
    for (uint32_t& v : pgsr_) r.Read(v);
    for (uint32_t& v : pcmd_) r.Read(v);
}

}  /* namespace */

REGISTER_SERVICE(Pxa27xPowerManager);
