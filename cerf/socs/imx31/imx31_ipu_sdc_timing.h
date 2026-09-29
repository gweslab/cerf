#pragma once

#include "../raster_scan_clock.h"

#include <cstdint>

struct Imx31SdcTimingRegs {
    uint32_t com_conf    = 0;
    uint32_t hor         = 0;
    uint32_t ver         = 0;
    uint32_t bg_pos      = 0;
    uint32_t disp3_time  = 0;
    uint32_t hsp_clk_per = 0;
    uint32_t acc_cc      = 0;
    uint16_t bg_fw       = 0;
    uint16_t bg_fh       = 0;
};

class Imx31SdcTiming {
public:
    static const char*            Unmodelled(const Imx31SdcTimingRegs& r);
    static RasterScanClock::Frame Frame(const Imx31SdcTimingRegs& r);
    static uint64_t               BgFirstTick(const Imx31SdcTimingRegs& r);
    static uint32_t               PerWr(const Imx31SdcTimingRegs& r);
    static uint32_t               HspPeriod(const Imx31SdcTimingRegs& r);
    static uint32_t               ClocksPerWord(const Imx31SdcTimingRegs& r);
    static bool                   SameScan(const Imx31SdcTimingRegs& a,
                                           const Imx31SdcTimingRegs& b);
};
