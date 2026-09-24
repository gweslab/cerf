#include "../vr41xx/vr41xx_pmu_impl.h"

#include "../../core/cerf_emulator.h"
#include "../../core/log.h"
#include "vr4122_clock_state.h"

#include <cstdint>
#include "vr4122_id.h"

namespace {

using cerf_vr41xx_pmu_detail::kOffWaitReg;
using cerf_vr41xx_pmu_detail::Vr41xxPmuBase;
using cerf_vr41xx_pmu_detail::Vr41xxPmuModel;

/* VR4122 PMU at 0x0F0000C0 (NetBSD sys/arch/hpcmips/vr/vripreg.h VR4122_PMU_ADDR);
   registers per the VR4131 UM U15350EJ2V0UM Table 1-6, 16-bit, incl.
   PMUTCLKDIVREG@0x0C + PMUINTRCLKDIVREG@0x0E; RTC follows at 0x0F000100
   (Table 1-7). */
constexpr Vr41xxPmuModel kModel = {
    /*base=*/0x0F0000C0u,
    /*size=*/0x40u,
    /* PMUINTREG (VR4131 UM 12.2.1), "Cleared to 0 when 1 is written": D15-12
       GPIO(3:0)INTR, D11 CLKRUNINTR, D9 RTCINTR, D8 BATTINH, D5 TIMOUTRST,
       D4 RTCRST, D3 RSTSW, D1 BATTINTR, D0 POWERSWINTR. D10 DCDST is the DCD#
       pin (R); D2 RFU reads 0. */
    /*int_w1c=*/0xFB3Bu,
    /*int_sw_rw=*/0x00C0u,     /* D7:6 memo(1:0), "can be used by users freely" */
    /*int_power_on=*/0x0010u,  /* RTCRST row: RTCRST(D4) = 1; D3 "holds", modeled 0 */
    /* PMUCNTREG (VR4131 UM 12.2.2): D15-12 GPIO(3:0)MSK, D11-8 GPIO(3:0)TRG,
       D7 STANDBY, D3 PLLOFFEN, D2 HALTIMERRST are R/W; D6:4 and D0 are RFU
       reading 0. */
    /*cnt_writable=*/0xFF8Cu,
    /*cnt_fixed_read=*/0x0002u,  /* D1 RFU: "Write 1. 1 is returned after a read." */
    /*cnt_power_on=*/0x8802u,    /* RTCRST row: GPIO3MSK(D15) + GPIO3TRG(D11) + D1 */
    /* PMUWAITREG (VR4131 UM 12.2.5): D13:0 WCOUNT, "Activation wait time =
       (WCOUNT(13:0) + 1) x (1/32.768) ms"; D15:14 RFU. "This register is set to
       0x2C00 (343.78 ms) after an RTC reset". */
    0x3FFFu,
    0x2C00u,
    0x0008u,   /* PMUINTREG D3 RSTSW  */
    0x0010u,   /* PMUINTREG D4 RTCRST */
};

constexpr uint32_t kOffInt2Reg = 0x04u;
constexpr uint32_t kOffCnt2Reg = 0x06u;

/* PMUINT2REG (VR4131 UM 12.2.3): D15-12 GPIO(12:9)INTR W1C; D11:0 RFU read 0;
   RTCRST row all 0. */
constexpr uint16_t kInt2W1c = 0xF000u;

/* PMUCNT2REG (VR4131 UM 12.2.4): D15-12 GPIO(12:9)MSK, D11-8 GPIO(12:9)TRG,
   D4 SOFTRST ("Software reset switch setting"); RTCRST row all 0. */
constexpr uint16_t kCnt2Writable = 0xFF10u;
constexpr uint16_t kCnt2SoftRst  = 0x0010u;

/* PMUTCLKDIVREG (VR4131 UM 12.2.6, 0x0F0000CC): D8 TDIV + D2:0 VTDIV(2:0) R/W,
   D15:9/D7:3 RFU read 0; cleared to 0 at RTC reset (VTDIV 000 = CLKSEL strap mode). */
constexpr uint32_t kOffTclkDivReg   = 0x0Cu;
constexpr uint16_t kTclkDivWritable = 0x0107u;

class Vr4122Pmu : public Vr41xxPmuBase<SocId::Vr4122, kModel> {
public:
    using Vr41xxPmuBase::Vr41xxPmuBase;

    /* Table 1-1 (VR4100 Series UM U15509EJ2V0UM): the VR4122's on-chip unit list
       carries no watchdog timer. */
    void LatchWatchdogReset() override {
        LOG(Caution, "Vr4122Pmu::LatchWatchdogReset: no watchdog unit on the VR4122\n");
        CerfFatalExit(CERF_FATAL_RUNTIME_ERROR);
    }

    /* PMUINTREG D0 POWERSWINTR "is not set to 1 when the POWER signal becomes
       high in Hibernate mode (MPOWER = 0)" (VR4131 UM 12.2.1). */
    void LatchSleepWakeCause() override {}
    void ClearSleepWakeCause() override {}

    void SaveState(StateWriter& w) override {
        Vr41xxPmuBase::SaveState(w);
        w.Write("int2reg", int2reg_);
        w.Write("cnt2reg", cnt2reg_);
        emu_.Get<Vr4122ClockState>().SaveState(w);
    }

    void RestoreState(StateReader& r) override {
        Vr41xxPmuBase::RestoreState(r);
        r.Read("int2reg", int2reg_);
        r.Read("cnt2reg", cnt2reg_);
        emu_.Get<Vr4122ClockState>().RestoreState(r);
    }

protected:
    void ResetExt() override {
        int2reg_ = 0;
        cnt2reg_ = 0;
    }

    uint16_t ReadHalfExt(uint32_t addr) override {
        switch (addr - kModel.base) {
            case kOffInt2Reg: return int2reg_;
            case kOffCnt2Reg: return cnt2reg_;
            case kOffWaitReg: return waitreg_;
            case kOffTclkDivReg: return emu_.Get<Vr4122ClockState>().Pending();
            default: return Vr41xxPmuBase::ReadHalfExt(addr);
        }
    }

    void WriteHalfExt(uint32_t addr, uint16_t value) override {
        switch (addr - kModel.base) {
            case kOffInt2Reg:
                int2reg_ = static_cast<uint16_t>(int2reg_ & ~(value & kInt2W1c));
                return;
            case kOffCnt2Reg:
                if (value & kCnt2SoftRst) {
                    LOG(Caution, "Vr4122Pmu: PMUCNT2REG SOFTRST=1 write (0x%04X) - "
                            "software-reset flow not modeled\n", value);
                    CerfFatalExit(CERF_FATAL_RUNTIME_ERROR);
                }
                cnt2reg_ = static_cast<uint16_t>(value & kCnt2Writable);
                return;
            case kOffTclkDivReg:
                emu_.Get<Vr4122ClockState>().SetPending(
                    static_cast<uint16_t>(value & kTclkDivWritable));
                return;
            default: Vr41xxPmuBase::WriteHalfExt(addr, value); return;
        }
    }

private:
    uint16_t int2reg_ = 0;
    uint16_t cnt2reg_ = 0;
};

}  /* namespace */

REGISTER_SERVICE(Vr4122Pmu);
