#include "imx31_cspi_engine.h"

#include <cstdint>

namespace {

/* MCIMX31RM Table 24-4 CSPI Register Summary (offsets from the port's base). */
constexpr uint32_t kOffRxdata    = 0x00u;
constexpr uint32_t kOffTxdata    = 0x04u;
constexpr uint32_t kOffConreg    = 0x08u;
constexpr uint32_t kOffIntreg    = 0x0Cu;
constexpr uint32_t kOffDmareg    = 0x10u;
constexpr uint32_t kOffStatreg   = 0x14u;
constexpr uint32_t kOffPeriodreg = 0x18u;
constexpr uint32_t kOffTestreg   = 0x1Cu;

/* MCIMX31RM Table 24-7 CONREG fields. */
constexpr uint32_t kConregEn      = 1u << 0;
constexpr uint32_t kConregXch     = 1u << 2;
constexpr uint32_t kConregCsShift = 24;
constexpr uint32_t kConregCsMask  = 0x3u << kConregCsShift;

/* MCIMX31RM Table 24-10 STATREG. */
constexpr uint32_t kStatTc = 1u << 8;  /* Transfer Completed (w1c) */
constexpr uint32_t kStatBo = 1u << 7;  /* Bit Counter Overflow (w1c) */
constexpr uint32_t kStatRr = 1u << 3;  /* RXFIFO Ready (≥1 word) */
constexpr uint32_t kStatTh = 1u << 1;  /* TXFIFO Half Empty */
constexpr uint32_t kStatTe = 1u << 0;  /* TXFIFO Empty */
constexpr uint32_t kStatW1cMask     = kStatTc | kStatBo;
/* §24.3.3.6: when EN=0, STATREG forcefully reads 0x0003. */
constexpr uint32_t kStatregDisabled = kStatTh | kStatTe;

}  /* namespace */

uint32_t Imx31CspiEngine::ReadWord(uint32_t addr) {
    const uint32_t off = addr - MmioBase();
    switch (off) {
        case kOffRxdata: {
            const uint32_t v = last_rxdata_;
            /* Reading RXDATA drains one FIFO entry; with single-shot
               exchanges that returns the FIFO to empty. */
            statreg_ &= ~kStatRr;
            return v;
        }
        case kOffConreg:    return conreg_;
        case kOffIntreg:    return intreg_;
        case kOffDmareg:    return dmareg_;
        case kOffStatreg:
            if ((conreg_ & kConregEn) == 0) return kStatregDisabled;
            return statreg_;
        case kOffPeriodreg: return periodreg_;
        case kOffTestreg:   return testreg_;
    }
    HaltUnsupportedAccess("ReadWord", addr, 0);
}

void Imx31CspiEngine::WriteWord(uint32_t addr, uint32_t value) {
    const uint32_t off = addr - MmioBase();
    switch (off) {
        case kOffTxdata:
            last_txdata_ = value;
            statreg_ &= ~kStatTe;
            return;
        case kOffConreg: {
            conreg_ = value;
            if ((value & kConregXch) && (value & kConregEn)) {
                const uint32_t cs = (value & kConregCsMask) >> kConregCsShift;
                last_rxdata_ = SpiExchange(cs, last_txdata_);
                /* Table 24-10: TC fires on shift-in of last bit; RR fires
                   once ≥1 word is in RXFIFO; TX FIFO drains to empty. */
                statreg_ |= kStatTc | kStatRr | kStatTh | kStatTe;
            }
            return;
        }
        case kOffIntreg:    intreg_    = value; return;
        case kOffDmareg:    dmareg_    = value; return;
        case kOffStatreg:
            statreg_ &= ~(value & kStatW1cMask);
            return;
        case kOffPeriodreg: periodreg_ = value; return;
        case kOffTestreg:   testreg_   = value; return;
    }
    HaltUnsupportedAccess("WriteWord", addr, value);
}
