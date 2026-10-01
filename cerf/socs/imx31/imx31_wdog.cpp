#include "../freescale_wdog_impl.h"

#include "imx31_ccm.h"
#include "imx31_id.h"

namespace {

using cerf_freescale_wdog_detail::FreescaleWdogBase;
using cerf_freescale_wdog_detail::kWcrReset;
using cerf_freescale_wdog_detail::kWcrWdbg;
using cerf_freescale_wdog_detail::kWcrWde;
using cerf_freescale_wdog_detail::kWcrWdzst;
using cerf_freescale_wdog_detail::WdogResetSource;

/* MCIMX31RM Table 37-6: bit 7 reserved; WRE, WDBG and WDZST write once-only; WDE can
   only be written to 1. */
constexpr uint16_t kWcrWoe       = 1u << 6;
constexpr uint16_t kWcrWre       = 1u << 3;
constexpr uint16_t kWcrWritable  = 0xFF7Fu;
constexpr uint16_t kWcrWriteOnce = kWcrWre | kWcrWdbg | kWcrWdzst;

/* MCIMX31RM Table 37-8. */
constexpr uint16_t kWrsrSftw = 1u << 0;
constexpr uint16_t kWrsrTout = 1u << 1;
constexpr uint16_t kWrsrExt  = 1u << 3;
constexpr uint16_t kWrsrPwr  = 1u << 4;

class Imx31Wdog : public FreescaleWdogBase<0x53FDC000u, SocId::Imx31> {
public:
    using FreescaleWdogBase::FreescaleWdogBase;

protected:
    uint64_t CkilHz() const override { return emu_.Get<Imx31Ccm>().CkilHz(); }
    uint16_t WcrWritable() const override { return kWcrWritable; }
    uint16_t WcrWriteOnce() const override { return kWcrWriteOnce; }
    uint16_t WcrWriteOneOnce() const override { return kWcrWde; }

    void OnWriteOnceChange(uint16_t value) override {
        emu_.Get<Fatal>().Die("Imx31Wdog: WCR write 0x%04X changes a write-once bit of 0x%04X",
                              value, wcr_);
    }

    bool SuspendedIn(FreescaleLowPowerMode mode) const override {
        return (wcr_ & kWcrWdzst) != 0u && mode != FreescaleLowPowerMode::kRun;
    }

    /* MCIMX31RM Figure 37-1. */
    bool SuspendStopsPrescaler() const override { return false; }

    void OnWdaChange() override {
        if ((wcr_ & cerf_freescale_wdog_detail::kWcrWda) == 0u) {
            emu_.Get<Fatal>().Die("Imx31Wdog: WCR 0x%04X asserts the WDOG signal; the pin is "
                                  "not modeled", wcr_);
        }
    }

    void OnCounterTimeout() override {
        if ((wcr_ & kWcrWre) != 0u) {
            emu_.Get<Fatal>().Die("Imx31Wdog: time-out with WCR 0x%04X asserts the WDOG "
                                  "signal; the pin is not modeled", wcr_);
        }
        RaiseReset(WdogResetSource::kTimeout);
    }

    void OnPowerOn(uint64_t) override {
        wcr_  = kWcrReset;
        wsr_  = 0u;
        wrsr_ = kWrsrPwr;
    }

    /* MCIMX31RM 37.5.2: a system reset restores every register but WRSR; Table 37-6 WOE
       survives a software reset only. Table 37-8: WRSR names the last reset source. */
    void ResetRegisters(ResetLineKind kind, WdogResetSource source, uint64_t) override {
        const uint16_t woe = source == WdogResetSource::kSoftware ? (wcr_ & kWcrWoe) : 0u;
        wcr_ = static_cast<uint16_t>(kWcrReset | woe);
        wsr_ = 0u;
        switch (kind) {
            case ResetLineKind::Rtc:   wrsr_ = kWrsrPwr; break;
            case ResetLineKind::Other: wrsr_ = kWrsrExt; break;
            case ResetLineKind::Watchdog:
                wrsr_ = source == WdogResetSource::kTimeout ? kWrsrTout : kWrsrSftw;
                break;
        }
    }
};

}

REGISTER_SERVICE(Imx31Wdog);
