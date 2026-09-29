#pragma once

#include "../freescale_timer_clocks.h"
#include "../raster_scan_peripheral.h"
#include "imx31_ipu_cpm.h"
#include "imx31_ipu_sdc_timing.h"

#include <cstdint>

class Imx31Ipu : public RasterScanPeripheral {
public:
    using RasterScanPeripheral::RasterScanPeripheral;

    using PfsKind       = Imx31IpuCpm::PfsKind;
    using ChannelFormat = Imx31IpuCpm::ChannelFormat;

    bool ShouldRegister() override;
    void OnReady() override;

    uint32_t MmioBase() const override { return 0x53FC0000u; }
    uint32_t MmioSize() const override { return 0x00004000u; }

    uint32_t ReadWord (uint32_t addr) override;
    void     WriteWord(uint32_t addr, uint32_t value) override;

    void SaveState(StateWriter& w) override;
    void RestoreState(StateReader& r) override;
    void PostRestore() override;

    bool          IsEnabled()        const;
    uint32_t      GetGuestW()        const;
    uint32_t      GetGuestH()        const;
    uint32_t      GetSdcBgFbPa()     const;
    ChannelFormat GetSdcBgFormat()   const;

    void SetupSdcScanout(uint32_t fb_pa, uint32_t w, uint32_t h);

protected:
    ScanShape              ScanShapeLocked() const override;
    RasterScanClock::Frame ScanFrameLocked() const;
    bool                   EdgeRaisesInterruptLocked(uint32_t edge_index,
                                                     bool this_frame) const override;
    void                   FrameEdgeLocked(uint32_t edge_index) override;
    void                   ScanEdgesRan() override;

private:
    static constexpr uint32_t kRegCount = 112u;
    static constexpr uint32_t kLastOff  = 0x1BCu;

    struct Lines {
        bool functional = false;
        bool error      = false;
    };

    void        ApplyResetsLocked();
    void        WriteRegLocked(uint32_t off, uint32_t value);
    void        OnIpuConfWriteLocked(uint32_t old_conf, uint32_t new_conf, uint64_t now);
    void        PublishSdcDimsLocked();
    void        EffectiveDimsLocked(uint32_t* w, uint32_t* h) const;
    Imx31SdcTimingRegs SdcRegsLocked() const;
    void        LatchScanTimingLocked();
    void        RequireStableScanLocked(uint32_t off) const;
    void        FrameStartLocked();
    uint32_t    IdmacBusyLocked(uint64_t now) const;
    Lines       LinesLocked() const;
    void        PublishLines(const Lines& lines);
    void        OnIdle();
    void        RequireIpuClockLocked(FreescaleLowPowerMode mode, const char* when) const;

    Imx31IpuCpm* cpm_ = nullptr;

    uint32_t regs_[kRegCount] = {};
    uint32_t last_pub_w_      = 0;
    uint32_t last_pub_h_      = 0;
    bool     bg_in_frame_     = false;
    Imx31SdcTimingRegs latched_sdc_;
};
