#include "../vr41xx/vr41xx_pmu_impl.h"

#include "../../core/cerf_emulator.h"

#include <cstdint>
#include "vr4121_id.h"

namespace {

using cerf_vr41xx_pmu_detail::Vr41xxPmuBase;
using cerf_vr41xx_pmu_detail::Vr41xxPmuModel;

/* VR4121 PMU, Internal I/O Space 2 (UM Table 1-6): PMUINTREG@0x00, PMUCNTREG@0x02,
   PMUINT2REG@0x04, PMUCNT2REG@0x06, PMUWAITREG@0x08, PMUDIVREG@0x0C, 16-bit. The RTC
   block follows at 0x0B0000C0 (UM Table 1-7), so the PMU decodes 0x0B0000A0-BF. */
constexpr Vr41xxPmuModel kModel = {
    /*base=*/0x0B0000A0u,
    /*size=*/0x20u,
    /* PMUINTREG (UM 16.2.1), "Cleared to 0 when 1 is written": D15-12 GPIOxINTR,
       D9 RTCINTR, D8 BATTINH, D5 TIMOUTRST, D4 RTCRST, D3 RSTSW, D2 DMSRST,
       D1 BATTINTR, D0 POWERSWINTR. D11 RFU reads 0; D10 DCDST is the DCD# pin. */
    /*int_w1c=*/0xF33Fu,
    /*int_sw_rw=*/0x00C0u,     /* D7:6 memo(1:0), "can be used by users freely" */
    /*int_power_on=*/0x0010u,  /* RTCRST column: RTCRST(D4) = 1, every other bit 0 */
    /* PMUCNTREG (UM 16.2.2): D15-12 GPIO(3:0)MSK, D11-8 GPIO(3:0)TRG, D7 STANDBY and
       D2 HALTIMERRST are R/W; D6:3 and D0 are RFU reading 0. HALTIMERRST is stored
       with NO HALTimer modeled behind it; UM 16.1.2(1) p398 gives its expiry as a
       reset of "all peripheral units except for RTC and PMU" plus a CPU cold reset. */
    /*cnt_writable=*/0xFF84u,
    /*cnt_fixed_read=*/0x0002u,  /* D1 RFU: "Write 1 to this bit. 1 is returned after a read." */
    /*cnt_power_on=*/0x8802u,    /* RTCRST column: "The GPIO3MSK bit is set to 1 by RTCRST,
                                    and the other bits are cleared to 0" - D15 + D11 + D1. */
    /* PMUWAITREG (UM 16.2.5, p415): D13:0 WCOUNT R/W, D15:14 RFU R. "This register is
       set to 0x2C00 ... after RTC reset"; its After-reset row is "Hold the value
       before reset". */
    0x3FFFu,
    0x2C00u,
    0x0008u,   /* PMUINTREG D3 RSTSW  */
    0x0010u,   /* PMUINTREG D4 RTCRST */
    /* Software shutdown's PMUINTREG column is "-" (UM Table 16-2), and D0 POWERSWINTR "is
       not set to 1 when the POWER signal becomes high in the Hibernate mode (MPOWER = 0)"
       (UM 16.2.1). */
    0u,
    /* UM 16.2.2 p412: D6:3 "Write 0 to these bits", D1 "Write 1 to this bit", D0
       "Write 0 to this bit". */
    0x0079u,
    0x0002u,
    /* UM 16.2.1 p409: PMUINTREG "After reset" row 0 in D15-D0. */
    0x0000u,
    /* UM 16.2.1 p410: "When a deadman's switch interrupt request has occurred, the DMSRST
       bit and the RSTSW bit are both set." */
    0x000Cu,
};

constexpr uint32_t kOffDivReg   = 0x0Cu;
constexpr uint16_t kDivWritable = 0x000Fu;

constexpr bool DivModeDefined(uint16_t value) {
    const uint16_t div = static_cast<uint16_t>(value & kDivWritable);
    return div <= 0x6u || div == 0x9u || div == 0xAu;
}

class Vr4121Pmu : public Vr41xxPmuBase<SocId::Vr4121, kModel> {
public:
    using Vr41xxPmuBase::Vr41xxPmuBase;

    void SaveState(StateWriter& w) override {
        Vr41xxPmuBase::SaveState(w);
        w.Write("divreg", divreg_);
    }

    void RestoreState(StateReader& r) override {
        Vr41xxPmuBase::RestoreState(r);
        r.Read("divreg", divreg_);
        if ((divreg_ & ~kDivWritable) != 0u || !DivModeDefined(divreg_)) {
            r.Reject("Vr4121Pmu: restored PMUDIVREG 0x%04X is no DIV mode a write stores", divreg_);
        }
    }

protected:
    void ResetExt() override { divreg_ = 0; }

    uint16_t ReadHalfExt(uint32_t addr) override {
        if (addr - kModel.base == kOffDivReg) return divreg_;
        return Vr41xxPmuBase::ReadHalfExt(addr);
    }

    void WriteHalfExt(uint32_t addr, uint16_t value) override {
        if (addr - kModel.base != kOffDivReg) {
            Vr41xxPmuBase::WriteHalfExt(addr, value);
            return;
        }
        if (!DivModeDefined(value)) {
            HaltUnsupportedAccess("PMUDIVREG WriteHalf with an RFU DIV mode", addr, value);
        }
        divreg_ = static_cast<uint16_t>(value & kDivWritable);
    }

private:
    uint16_t divreg_ = 0;
};

}  /* namespace */

REGISTER_SERVICE_AS(Vr4121Pmu, Vr41xxPmu);
