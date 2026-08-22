#pragma once

#include "../../peripherals/peripheral_base.h"

#include <cstdint>
#include <mutex>

/* Intel PXA27x Developer's Manual 280000-001 Section 7.6 Table 7-64: LCD
   controller registers, 0x4400_0000..0x4400_026C. */
class Pxa27xLcd : public Peripheral {
public:
    using Peripheral::Peripheral;

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

    /* Intel PXA27x Developer's Manual 280000-001 Section 7.5.1.2.1: the next
       frame Descriptor pointed to by FDADRx is loaded into the registers of the
       associated DMA channel after all of the data for the current Descriptor
       has been transferred. */
    void AdvanceFrame();

private:
    /* Intel PXA27x Developer's Manual 280000-001 Table 7-64. */
    static constexpr uint32_t kLccr0 = 0x000u;
    static constexpr uint32_t kLccr1 = 0x004u;
    static constexpr uint32_t kLccr2 = 0x008u;
    static constexpr uint32_t kLccr3 = 0x00Cu;
    static constexpr uint32_t kLccr4 = 0x010u;
    static constexpr uint32_t kLccr5 = 0x014u;
    static constexpr uint32_t kFbr0  = 0x020u;
    static constexpr uint32_t kFbr4  = 0x030u;
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
    static constexpr uint32_t kFbr5   = 0x110u;
    static constexpr uint32_t kFbr6   = 0x114u;
    static constexpr uint32_t kDmaBase = 0x200u;
    static constexpr uint32_t kDmaEnd  = 0x270u;

    static constexpr uint32_t kChannels = 7u;

    uint32_t ReadRegLocked (uint32_t off);
    void     WriteRegLocked(uint32_t off, uint32_t value);
    void     WriteLccr0Locked(uint32_t value);

    void LoadChannelDescriptorLocked(uint32_t channel);

    /* Intel PXA27x Developer's Manual 280000-001 Section 7.5.22: LIIDR is only
       written when an unmasked interrupt is signaled and there are no other
       unmasked interrupts pending. */
    void LatchInterruptIdLocked(uint32_t unmasked_before, uint32_t frame_id);

    uint32_t UnmaskedStatusLocked() const;
    bool     IrqPendingLocked() const;
    void     PublishIrq(bool pending);

    static bool IsKnown(uint32_t off);

    mutable std::mutex state_mtx_;

    /* Intel PXA27x Developer's Manual 280000-001 Tables 7-40..7-45 reset
       column. */
    uint32_t lccr_[6] = {};
    /* Intel PXA27x Developer's Manual 280000-001 Table 7-58 reset column. */
    uint32_t lcsr0_ = 0;
    /* Intel PXA27x Developer's Manual 280000-001 Table 7-59 reset column. */
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

    /* Intel PXA27x Developer's Manual 280000-001 Table 7-54 FDADR0/1/2/3/4/5/6,
       Table 7-61 FSADR, Table 7-62 FIDR, Table 7-63 LDCMD, Table 7-55 FBR. */
    uint32_t fdadr_[kChannels] = {};
    uint32_t fsadr_[kChannels] = {};
    uint32_t fidr_ [kChannels] = {};
    uint32_t ldcmd_[kChannels] = {};
    uint32_t fbr_  [kChannels] = {};
};
