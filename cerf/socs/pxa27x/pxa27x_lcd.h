#pragma once

#include "../raster_scan_peripheral.h"

#include <cstdint>

class Pxa27xLcdDma;

/* Intel PXA27x Developer's Manual 280000-001 Section 7.6 Table 7-64: LCD
   controller registers, 0x4400_0000..0x4400_026C. */
class Pxa27xLcd : public RasterScanPeripheral {
public:
    using RasterScanPeripheral::RasterScanPeripheral;

    /* Intel PXA27x Developer's Manual 280000-001 Table 7-43: BPP3:BPP = 0b0100
       selects 16 bpp with no palette. Section 7.4.1.3: the palette RAM is bypassed
       for pixel depth greater than 8 bpp. */
    static constexpr uint32_t kBppCode16Bpp       = 0x4u;
    static constexpr uint32_t kBytesPerPixel16Bpp = 2u;

    bool ShouldRegister() override;
    void OnReady() override;

    uint32_t MmioBase() const override { return 0x44000000u; }
    uint32_t MmioSize() const override { return 0x00001000u; }

    uint32_t ReadWord (uint32_t addr) override;
    void     WriteWord(uint32_t addr, uint32_t value) override;

    void SaveState(StateWriter& w) override;
    void RestoreState(StateReader& r) override;
    void PostRestore() override;

    /* Intel PXA27x Developer's Manual 280000-001 Table 7-40 bit 0 ENB. */
    bool IsEnabled() const;

    /* Intel PXA27x Developer's Manual 280000-001 Table 7-41 bits 9:0 PPL:
       "Actual pixel per line = PPL+1". */
    uint32_t GetGuestW() const;
    /* Intel PXA27x Developer's Manual 280000-001 Table 7-42 bits 9:0 LPP:
       "Lines/panel = (LPP+1)". */
    uint32_t GetGuestH() const;

    /* Intel PXA27x Developer's Manual 280000-001 Table 7-43 bits 29 BPP3 and
       26:24 BPP. */
    uint32_t GetBppCode() const;

    /* Intel PXA27x Developer's Manual 280000-001 Table 7-61 bits 31:4
       SRCADDR: address of the palette or pixel frame data in memory. */
    uint32_t GetChannelSrcPa(uint32_t channel) const;
    /* Intel PXA27x Developer's Manual 280000-001 Table 7-63 bits 20:2 LENGTH
       and bit 26 PAL. */
    uint32_t GetChannelLength(uint32_t channel) const;
    bool     ChannelIsPalette(uint32_t channel) const;

protected:
    ScanShape              ScanShapeLocked() const override;
    RasterScanClock::Frame ScanFrameLocked() const;
    bool      EdgeRaisesInterruptLocked(uint32_t edge_index, bool) const override;
    void      FrameEdgeLocked(uint32_t edge_index) override;
    void      ScanEdgesRan() override;

private:
    /* Intel PXA27x Developer's Manual 280000-001 Table 7-64. */
    static constexpr uint32_t kLccr0 = 0x000u;
    static constexpr uint32_t kLccr1 = 0x004u;
    static constexpr uint32_t kLccr2 = 0x008u;
    static constexpr uint32_t kLccr3 = 0x00Cu;
    static constexpr uint32_t kLccr4 = 0x010u;
    static constexpr uint32_t kLccr5 = 0x014u;
    static constexpr uint32_t kLcsr1 = 0x034u;
    static constexpr uint32_t kLcsr0 = 0x038u;
    static constexpr uint32_t kLiidr = 0x03Cu;
    static constexpr uint32_t kTrgbr = 0x040u;
    static constexpr uint32_t kTcr   = 0x044u;
    static constexpr uint32_t kOvl1c1 = 0x050u;
    static constexpr uint32_t kOvl1c2 = 0x060u;
    static constexpr uint32_t kOvl2c1 = 0x070u;
    static constexpr uint32_t kOvl2c2 = 0x080u;
    static constexpr uint32_t kCcr    = 0x090u;
    static constexpr uint32_t kCmdcr  = 0x100u;
    static constexpr uint32_t kPrsr   = 0x104u;

    template <typename F> void VisitRegs(F& f);

    uint32_t* RegSlotLocked(uint32_t off);
    void      WriteRegLocked(uint32_t off, uint32_t value, uint64_t now);
    void      WriteLccr0Locked(uint32_t value, uint64_t now);
    void      RequireStableTimingLocked(uint32_t off, uint32_t value) const;
    void      RequirePlaneDisabled(const char* reg, uint32_t value, uint32_t enable) const;
    void      ResetRegistersLocked();

    bool LoadChannel0DescriptorLocked();
    void LoadFrameDescriptorLocked();
    void RequireWholeFrameDescriptorLocked() const;

    uint32_t BppCodeLocked() const;

    const char* UnmodelledScanLocked() const;

    void LatchInterruptIdLocked(uint32_t unmasked_before, uint32_t frame_id);

    uint32_t UnmaskedStatusLocked() const;
    bool     IrqPendingLocked() const;
    void     PublishIrq(bool pending);

    static bool IsKnown(uint32_t off);

    Pxa27xLcdDma* dma_ = nullptr;

    uint32_t lccr_[6] = {};
    uint32_t lcsr0_ = 0;
    uint32_t lcsr1_ = 0;
    /* Intel PXA27x Developer's Manual 280000-001 Table 7-60 IFRAMEID. */
    uint32_t liidr_ = 0;
    uint32_t trgbr_ = 0;
    uint32_t tcr_   = 0;
    uint32_t cmdcr_ = 0;
    uint32_t prsr_  = 0;
    uint32_t ovl1c1_ = 0;
    uint32_t ovl1c2_ = 0;
    uint32_t ovl2c1_ = 0;
    uint32_t ovl2c2_ = 0;
    uint32_t ccr_    = 0;
};
