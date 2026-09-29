#pragma once

#include "../raster_scan_peripheral.h"

#include <cstdint>
#include <mutex>

class Omap3530CmDss;

class Omap3530Dss : public RasterScanPeripheral {
public:
    using RasterScanPeripheral::RasterScanPeripheral;

    bool ShouldRegister() override;
    void OnReady() override;

    uint32_t MmioBase() const override { return 0x48050000u; }
    uint32_t MmioSize() const override { return 0x00001000u; }

    uint32_t ReadWord (uint32_t addr) override;
    uint16_t ReadHalf (uint32_t addr) override;
    void     WriteWord(uint32_t addr, uint32_t value) override;

    void SaveState(StateWriter& w) override;
    void RestoreState(StateReader& r) override;
    void PostRestore() override;

    bool     IsScanning();
    uint32_t GetFbPa();
    uint32_t GetGuestW();
    uint32_t GetGuestH();
    uint32_t GetGfxFormat();

protected:
    ScanShape              ScanShapeLocked() const override;
    RasterScanClock::Frame ScanFrameLocked() const;
    bool                   EdgeRaisesInterruptLocked(uint32_t edge_index, bool) const override;
    void                   FrameEdgeLocked(uint32_t edge_index) override;
    void                   ScanEdgesRan() override;

private:
    static constexpr uint32_t kDispcBase  = 0x400u;
    static constexpr uint32_t kRfbiBase   = 0x800u;
    static constexpr uint32_t kVencBase   = 0xC00u;
    static constexpr uint32_t kBlockSize  = 0x400u;
    static constexpr uint32_t kBlockWords = kBlockSize / 4u;

    static constexpr uint32_t kDssRev       = 0x000u;
    static constexpr uint32_t kDssSysconfig = 0x010u;
    static constexpr uint32_t kDssSysstatus = 0x014u;
    static constexpr uint32_t kDssControl   = 0x040u;
    static constexpr uint32_t kDssSdiCtrl   = 0x044u;
    static constexpr uint32_t kDssPllCtrl   = 0x048u;
    static constexpr uint32_t kDssSdiStatus = 0x05Cu;

    static constexpr uint32_t kDispcRev        = 0x000u;
    static constexpr uint32_t kDispcSysconfig  = 0x010u;
    static constexpr uint32_t kDispcSysstatus  = 0x014u;
    static constexpr uint32_t kDispcIrqstatus  = 0x018u;
    static constexpr uint32_t kDispcIrqenable  = 0x01Cu;
    static constexpr uint32_t kDispcControl    = 0x040u;
    static constexpr uint32_t kDispcLineStatus = 0x05Cu;
    static constexpr uint32_t kDispcTimingH    = 0x064u;
    static constexpr uint32_t kDispcTimingV    = 0x068u;
    static constexpr uint32_t kDispcDivisor    = 0x070u;
    static constexpr uint32_t kDispcSizeLcd    = 0x07Cu;
    static constexpr uint32_t kDispcGfxBa0     = 0x080u;
    static constexpr uint32_t kDispcGfxAttribs = 0x0A0u;

    static constexpr uint32_t kSysconfigSoftReset = 1u << 1;
    static constexpr uint32_t kSysstatusResetDone = 1u << 0;

    /* SPRUF98Y Table 15-145 (printed p. 2447): DSS_CONTROL DISPC_CLK_SWITCH [0] and
       DSI_CLK_SWITCH [1], 0x0 DSS1_ALWON_FCLK; both reset to 0. */
    static constexpr uint32_t kDispcClkSwitch = 1u << 0;
    static constexpr uint32_t kDsiClkSwitch   = 1u << 1;

    /* Table 15-149 (printed p. 2449-2450): DSS_PLL_CONTROL SDI_PLL_GOBIT [28],
       SDI_PLL_SYSRESET [18] 0x0 "PLL under reset"; every field resets to 0. */
    static constexpr uint32_t kSdiPllGoBit    = 1u << 28;
    static constexpr uint32_t kSdiPllSysReset = 1u << 18;

    /* Table 15-151 (printed p. 2450-2451): DSS_SDI_STATUS DSS_DISPC_CLK1_STATUS [0]
       and DSS_DSI_CLK1_STATUS [7] read 1 while DSS1_ALWON_FCLK is selected. */
    static constexpr uint32_t kSdiStatusDispcAlwon = 1u << 0;
    static constexpr uint32_t kSdiStatusDsiAlwon   = 1u << 7;

    /* Table 15-163 (printed p. 2459-2461): DISPC_CONTROL; every field resets to 0. */
    static constexpr uint32_t kCtrlLcdEnable     = 1u << 0;
    static constexpr uint32_t kCtrlDigitalEnable = 1u << 1;
    static constexpr uint32_t kCtrlStnTft        = 1u << 3;
    static constexpr uint32_t kCtrlGoLcd         = 1u << 5;
    static constexpr uint32_t kCtrlStallMode     = 1u << 11;
    static constexpr uint32_t kCtrlTdmEnable     = 1u << 20;
    static constexpr uint32_t kCtrlScanModeBits  = kCtrlStnTft | kCtrlStallMode | kCtrlTdmEnable;

    static constexpr uint32_t kGfxAttrEnable = 1u << 0;

    /* Table 15-159 (printed p. 2454-2456): DISPC_IRQSTATUS FRAMEDONE [0], VSYNC [1];
       ACBIASCOUNTSTATUS [4], PROGRAMMEDLINENUMBER [5], GFXENDWINDOW [7],
       PALETTEGAMMALOADING [8], VID1ENDWINDOW [11], VID2ENDWINDOW [13]. */
    static constexpr uint32_t kIrqFrameDone        = 1u << 0;
    static constexpr uint32_t kIrqVsync            = 1u << 1;
    static constexpr uint32_t kIrqUnproducedEvents = 0x000029B0u;
    static constexpr uint32_t kIrqMask        = 0x1FFFFu;

    /* Table 15-181 (printed p. 2471): DISPC_DIVISOR LCD [23:16] reset 0x01,
       PCD [7:0] reset 0x02; LCD 0 and PCD 0 or 1 are invalid. */
    static constexpr uint32_t kDivisorReset = 0x00010002u;

    static constexpr int kIrqDss = 25;

    bool ShouldAssertIrqLocked() const;
    void RecomputeIrqLineLocked();
    void HandleDssSysconfigWriteLocked(uint32_t value);
    void HandleDssControlWriteLocked(uint32_t value);
    void HandleDispcSysconfigWriteLocked(uint32_t value);
    void HandleDispcIrqstatusWriteLocked(uint32_t value);
    void HandleDispcIrqenableWriteLocked(uint32_t value);
    bool HandleDispcControlWriteLocked(uint32_t value, uint64_t now);
    void HandleDispcScanTimingWriteLocked(uint32_t doff, uint32_t value);

    void        ApplyScanResetsLocked();
    void        ApplyDispcScanResetsLocked();
    const char* UnmodelledLcdLocked() const;
    uint32_t    SdiStatusLocked() const;
    uint32_t    VfpLinesLocked() const;
    uint32_t    DispcLineStatusLocked(uint64_t now) const;

    Omap3530CmDss* cm_dss_ = nullptr;

    uint32_t dss_top_[kBlockWords]{};
    uint32_t dispc_  [kBlockWords]{};
    uint32_t rfbi_   [kBlockWords]{};
    uint32_t venc_   [kBlockWords]{};
};
