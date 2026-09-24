#include "../freescale_wdog_impl.h"

#include "../../state/state_stream.h"
#include "imx31_id.h"

namespace {

using cerf_freescale_wdog_detail::FreescaleWdogBase;
using cerf_freescale_wdog_detail::kWcr;
using cerf_freescale_wdog_detail::kWsr;
using cerf_freescale_wdog_detail::kWrsr;
using cerf_freescale_wdog_detail::kWcrReset;

/* i.MX31 Watchdog (MCIMX31RM Ch 37) at PA 0x53FD_C000 - three 16-bit registers.
   The kernel loads WCR.WT, sets WDE, then services the dog (WSR 0x5555/0xAAAA)
   every cycle and reads WRSR for the boot reason. */
class Imx31Wdog : public FreescaleWdogBase<0x53FDC000u, SocId::Imx31> {
public:
    using FreescaleWdogBase::FreescaleWdogBase;

    /* WRSR is read-only (cold power-on signature) and recomputed, not stored;
       WCR and WSR are the whole writable state. */
    void SaveState(StateWriter& w) override    { w.Write("wcr", wcr_); w.Write("wsr", wsr_); }
    void RestoreState(StateReader& r) override { r.Read("wcr", wcr_); r.Read("wsr", wsr_); }

protected:
    uint16_t ReadReg16(uint32_t off) override {
        switch (off) {
            case kWcr:  return wcr_;
            case kWsr:  return wsr_;
            case kWrsr: return 0x0010u;  /* PWR: reset was power-on (Table 37-8) */
        }
        HaltUnsupportedAccess("ReadReg16", MmioBase() + off, 0);
    }
    void WriteReg16(uint32_t off, uint16_t value) override {
        switch (off) {
            case kWcr:  wcr_ = value; return;
            /* No time-out->reset timer: the kernel services the dog (WSR
               0x5555/0xAAAA) every cycle so a real watchdog never bites, and a
               reset timer would only fire a spurious mid-boot reset on
               host/guest timing skew. */
            case kWsr:  wsr_ = value; return;
            case kWrsr: return;  /* read-only (§37.5.4: write raises bus error) */
        }
        HaltUnsupportedAccess("WriteReg16", MmioBase() + off, value);
    }

private:
    uint16_t wcr_ = kWcrReset;
    uint16_t wsr_ = 0;
};

}  /* namespace */

REGISTER_SERVICE(Imx31Wdog);
