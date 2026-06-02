#include "../../peripherals/peripheral_base.h"

#include "../../core/cerf_emulator.h"
#include "../../boards/board_detector.h"
#include "../../peripherals/peripheral_dispatcher.h"
#include "imx31_avic.h"

#include <cstdint>

namespace {

/* i.MX31 SDHC1 — MCIMX31RM Ch 29 @0x5000_4000. No SD card wired; per §29.5.1 a
   command submit must raise the END_CMD_RESP interrupt (here: set END_CMD_RESP +
   TIME_OUT_RESP, assert AVIC source 9) or the driver wedges waiting on it. */
constexpr uint32_t kBase = 0x50004000u;
constexpr uint32_t kSize = 0x00000040u;  /* 16 32-bit regs, 0x00-0x3C (Table 29-2) */

constexpr uint32_t kStrStpClk  = 0x00u;
constexpr uint32_t kStatus     = 0x04u;  /* R/O, W1C event bits (Table 29-6) */
constexpr uint32_t kClkRate    = 0x08u;
constexpr uint32_t kCmdDatCont = 0x0Cu;  /* command submit (§29.5.1) */
constexpr uint32_t kResTo      = 0x10u;
constexpr uint32_t kReadTo     = 0x14u;
constexpr uint32_t kBlkLen     = 0x18u;
constexpr uint32_t kNob        = 0x1Cu;
constexpr uint32_t kRevNo      = 0x20u;  /* R/O */
constexpr uint32_t kIntCntr    = 0x24u;
constexpr uint32_t kCmd        = 0x28u;
constexpr uint32_t kArg        = 0x2Cu;
constexpr uint32_t kResFifo    = 0x34u;  /* R: response FIFO */
constexpr uint32_t kBufAccess  = 0x38u;  /* R/W: data FIFO */

constexpr uint32_t kClkStartClk    = 1u << 1;   /* STR_STP_CLK START_CLK (Ex 29-1) */
constexpr uint32_t kClkStopClk     = 1u << 0;   /* STR_STP_CLK STOP_CLK */
constexpr uint32_t kStsTimeOutResp = 1u << 1;   /* STATUS TIME_OUT_RESP (Table 29-6) */
constexpr uint32_t kStsCardClkRun  = 1u << 8;   /* STATUS CARD_BUS_CLK_RUN */
constexpr uint32_t kStsEndCmdResp  = 1u << 13;  /* STATUS END_CMD_RESP */
constexpr uint32_t kIntEndCmdResp  = 1u << 2;   /* INT_CNTR END_CMD_RESP enable (Table 29-14; §29.5.1 step 2) */
constexpr uint32_t kStatusReset    = 0x30000000u;  /* YBUF_EMPTY|XBUF_EMPTY (Table 29-2) */
constexpr uint32_t kRevNoVal       = 0x00000400u;
constexpr uint32_t kAvicSourceSdhc1 = 9u;  /* AVIC Table 2-3 */

class Imx31Sdhc1 : public Peripheral {
public:
    using Peripheral::Peripheral;

    bool ShouldRegister() override {
        auto* bd = emu_.TryGet<BoardDetector>();
        return bd && bd->GetSoc() == SocFamily::iMX31;
    }
    void OnReady() override { emu_.Get<PeripheralDispatcher>().Register(this); }

    uint32_t MmioBase() const override { return kBase; }
    uint32_t MmioSize() const override { return kSize; }

    uint32_t ReadWord(uint32_t addr) override {
        switch (addr - kBase) {
            case kStrStpClk:  return str_stp_clk_;
            case kStatus:     return status_;
            case kClkRate:    return clk_rate_;
            case kCmdDatCont: return cmd_dat_cont_;
            case kResTo:      return res_to_;
            case kReadTo:     return read_to_;
            case kBlkLen:     return blk_len_;
            case kNob:        return nob_;
            case kRevNo:      return kRevNoVal;
            case kIntCntr:    return int_cntr_;
            case kCmd:        return cmd_;
            case kArg:        return arg_;
            case kResFifo:    return 0;  /* no card -> no response data */
            case kBufAccess:  return 0;  /* no data transfer */
        }
        HaltUnsupportedAccess("ReadWord", addr, 0);
    }

    void WriteWord(uint32_t addr, uint32_t value) override {
        switch (addr - kBase) {
            case kStrStpClk:
                str_stp_clk_ = value;
                if (value & kClkStartClk) status_ |= kStsCardClkRun;
                if (value & kClkStopClk)  status_ &= ~kStsCardClkRun;
                return;
            /* W1C: writing 1 clears an event status bit (Table 29-6). */
            case kStatus:     status_ &= ~value; UpdateIrq(); return;
            case kClkRate:    clk_rate_ = value; return;
            /* Command submit (§29.5.1 step 5). No card -> the command times out:
               END_CMD_RESP (transfer done) + TIME_OUT_RESP (no response). */
            case kCmdDatCont:
                cmd_dat_cont_ = value;
                status_ |= kStsEndCmdResp | kStsTimeOutResp;
                UpdateIrq();
                return;
            case kResTo:      res_to_ = value; return;
            case kReadTo:     read_to_ = value; return;
            case kBlkLen:     blk_len_ = value; return;
            case kNob:        nob_ = value; return;
            case kIntCntr:    int_cntr_ = value; UpdateIrq(); return;
            case kCmd:        cmd_ = value; return;
            case kArg:        arg_ = value; return;
            case kBufAccess:  return;  /* no data transfer */
        }
        HaltUnsupportedAccess("WriteWord", addr, value);
    }

private:
    /* AVIC source 9 is asserted while END_CMD_RESP is set and its INT_CNTR[2]
       enable is on; the ISR W1C-clears END_CMD_RESP, which deasserts it. */
    void UpdateIrq() {
        const bool pending = (status_ & kStsEndCmdResp) && (int_cntr_ & kIntEndCmdResp);
        auto& avic = emu_.Get<Imx31Avic>();
        if (pending) avic.AssertSource(kAvicSourceSdhc1);
        else         avic.DeassertSource(kAvicSourceSdhc1);
    }

    uint32_t str_stp_clk_  = 0;
    uint32_t status_       = kStatusReset;
    uint32_t clk_rate_     = 0x00000008u;  /* reset (Table 29-2) */
    uint32_t cmd_dat_cont_ = 0;
    uint32_t res_to_       = 0x00000040u;  /* reset (Table 29-2) */
    uint32_t read_to_      = 0x0000FFFFu;  /* reset (Table 29-2) */
    uint32_t blk_len_      = 0;
    uint32_t nob_          = 0;
    uint32_t int_cntr_     = 0;
    uint32_t cmd_          = 0;
    uint32_t arg_          = 0;
};

}  /* namespace */

REGISTER_SERVICE(Imx31Sdhc1);
