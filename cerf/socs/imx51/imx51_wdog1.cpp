#include "../freescale_wdog_impl.h"

#include "../../state/state_stream.h"
#include "imx51_id.h"

namespace {

using cerf_freescale_wdog_detail::FreescaleWdogBase;
using cerf_freescale_wdog_detail::kWcr;
using cerf_freescale_wdog_detail::kWsr;
using cerf_freescale_wdog_detail::kWrsr;
using cerf_freescale_wdog_detail::kWicr;
using cerf_freescale_wdog_detail::kWmcr;
using cerf_freescale_wdog_detail::kWcrReset;

constexpr uint16_t kWicrReset = 0x0004u;  /* WICT=0x04 (MCIMX51RM Table 62-8) */
constexpr uint16_t kWmcrReset = 0x0001u;  /* PDE=1 (MCIMX51RM Table 62-9)     */

/* i.MX51 WDOG1 (MCIMX51RM Ch 62) at PA 0x73F9_8000 - five 16-bit registers
   (adds WICR/WMCR over i.MX31). The guest services the dog (WSR 0x5555/0xAAAA)
   every cycle and reads WRSR for the boot reason. */
class Imx51Wdog1 : public FreescaleWdogBase<0x73F98000u, SocId::Imx51> {
public:
    using FreescaleWdogBase::FreescaleWdogBase;

    /* WRSR is read-only (recomputed cold signature); WCR/WSR/WICR/WMCR are the
       writable state. */
    void SaveState(StateWriter& w) override {
        w.Write("wcr", wcr_); w.Write("wsr", wsr_); w.Write("wicr", wicr_); w.Write("wmcr", wmcr_);
    }
    void RestoreState(StateReader& r) override {
        r.Read("wcr", wcr_); r.Read("wsr", wsr_); r.Read("wicr", wicr_); r.Read("wmcr", wmcr_);
    }

protected:
    uint16_t ReadReg16(uint32_t off) override {
        switch (off) {
            case kWcr:  return wcr_;
            case kWsr:  return wsr_;
            case kWrsr: return 0x0000u;  /* TOUT/SFTW only, no PWR (Table 62-7); cold = 0 */
            case kWicr: return wicr_;
            case kWmcr: return wmcr_;
        }
        HaltUnsupportedAccess("ReadReg16", MmioBase() + off, 0);
    }
    void WriteReg16(uint32_t off, uint16_t value) override {
        switch (off) {
            case kWcr:  wcr_ = value; return;
            /* No time-out->reset timer: the guest services the dog (WSR
               0x5555/0xAAAA) every cycle so a real watchdog never bites, and a
               reset timer would only fire a spurious mid-boot reset on
               host/guest timing skew. */
            case kWsr:  wsr_  = value; return;
            case kWrsr: return;        /* read-only */
            case kWicr: wicr_ = value; return;
            case kWmcr: wmcr_ = value; return;
        }
        HaltUnsupportedAccess("WriteReg16", MmioBase() + off, value);
    }

private:
    uint16_t wcr_  = kWcrReset;
    uint16_t wsr_  = 0;
    uint16_t wicr_ = kWicrReset;
    uint16_t wmcr_ = kWmcrReset;
};

}  /* namespace */

REGISTER_SERVICE(Imx51Wdog1);
