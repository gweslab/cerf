#include "imx31_ipu_sdc_timing.h"

#include "../../core/bit_field.h"

namespace {

/* MCIMX31RM Figure 44-53 / Table 44-72. */
constexpr uint32_t kComSdcModeMask     = 0x3u;
constexpr uint32_t kComSdcModeTftColor = 0x1u;
constexpr uint32_t kComFgEn            = 1u << 4;
constexpr uint32_t kComMaskEn          = 1u << 8;
constexpr uint32_t kComSharp           = 1u << 12;
constexpr uint32_t kComSaveRefrEn      = 1u << 14;
constexpr uint32_t kComDualMode        = 1u << 15;
constexpr uint32_t kComCocMask         = 0x7u << 16;

/* MCIMX31RM Table 44-105: HSP_CLK_PERIOD_1 [6:0], HSP_CLK_PERIOD_2 [22:16], each an
   integer part [6:4] and a fractional part [3:0]. */
constexpr uint32_t kHspPeriodMask   = 0x7Fu;
constexpr uint32_t kHspPeriod2Shift = 16u;

}

uint32_t Imx31SdcTiming::PerWr(const Imx31SdcTimingRegs& r) {
    return cerf::BitField(r.disp3_time, 0u, 0xFFFu);
}

uint32_t Imx31SdcTiming::HspPeriod(const Imx31SdcTimingRegs& r) {
    return r.hsp_clk_per & kHspPeriodMask;
}

/* MCIMX31RM Table 44-137: DI_DISP_ACC_CC DISP3_IF_CLK_CNT_D [13:12], display clock
   cycles for one data word minus 1. */
uint32_t Imx31SdcTiming::ClocksPerWord(const Imx31SdcTimingRegs& r) {
    return cerf::BitField(r.acc_cc, 12u, 0x3u) + 1u;
}

bool Imx31SdcTiming::SameScan(const Imx31SdcTimingRegs& a, const Imx31SdcTimingRegs& b) {
    const RasterScanClock::Frame fa = Frame(a);
    const RasterScanClock::Frame fb = Frame(b);
    return fa.ticks == fb.ticks && fa.edge[0] == fb.edge[0] && BgFirstTick(a) == BgFirstTick(b) &&
           PerWr(a) == PerWr(b) && HspPeriod(a) == HspPeriod(b) &&
           ClocksPerWord(a) == ClocksPerWord(b);
}

const char* Imx31SdcTiming::Unmodelled(const Imx31SdcTimingRegs& r) {
    const uint32_t com = r.com_conf;
    if ((com & kComSdcModeMask) != kComSdcModeTftColor) return "an SDC_MODE other than TFT color";
    if (com & kComFgEn)       return "the foreground plane (FG_EN), whose scan-out is not modelled";
    if (com & kComMaskEn)     return "the mask plane (MASK_EN)";
    if (com & kComCocMask)    return "the hardware cursor (COC)";
    if (com & kComSharp)      return "Sharp panel signals (SHARP)";
    if (com & kComSaveRefrEn) return "saving refresh mode (SAVE_REFR_EN)";
    if (com & kComDualMode)   return "dual mode (DUAL_MODE)";
    if (PerWr(r) == 0u)       return "a zero DISP3_IF_CLK_PER_WR";
    /* MCIMX31RM §44.3.3.8.5: the HSP_CLK_PER_SEL signal from the Clock Controller
       picks HSP_CLK_PERIOD_1 or _2. */
    if (HspPeriod(r) != cerf::BitField(r.hsp_clk_per, kHspPeriod2Shift, kHspPeriodMask)) {
        return "HSP_CLK_PERIOD_1 and HSP_CLK_PERIOD_2 differing (HSP_CLK_PER_SEL)";
    }
    if (HspPeriod(r) == 0u) return "a zero HSP_CLK_PERIOD";
    if (cerf::BitField(r.bg_pos, 16u, 0x3FFu) + r.bg_fw > cerf::BitField(r.hor, 16u, 0x3FFu) ||
        cerf::BitField(r.bg_pos, 0u, 0x3FFu) + r.bg_fh > cerf::BitField(r.ver, 16u, 0x3FFu)) {
        return "a BG plane that exceeds the screen (Table 44-76)";
    }
    return nullptr;
}

RasterScanClock::Frame Imx31SdcTiming::Frame(const Imx31SdcTimingRegs& r) {
    const uint64_t line = cerf::BitField(r.hor, 16u, 0x3FFu) + 1u;
    RasterScanClock::Frame frame;
    frame.ticks   = line * (cerf::BitField(r.ver, 16u, 0x3FFu) + 1u);
    frame.edge[0] = cerf::BitField(r.hor, 0u, 0xFu) + (cerf::BitField(r.bg_pos, 0u, 0x3FFu) + r.bg_fh - 1u) * line +
                    cerf::BitField(r.bg_pos, 16u, 0x3FFu) + r.bg_fw;
    frame.edge[1] = frame.ticks;
    frame.edges   = 2u;
    return frame;
}

uint64_t Imx31SdcTiming::BgFirstTick(const Imx31SdcTimingRegs& r) {
    const uint64_t line = cerf::BitField(r.hor, 16u, 0x3FFu) + 1u;
    return cerf::BitField(r.hor, 0u, 0xFu) + cerf::BitField(r.bg_pos, 0u, 0x3FFu) * line +
           cerf::BitField(r.bg_pos, 16u, 0x3FFu);
}
