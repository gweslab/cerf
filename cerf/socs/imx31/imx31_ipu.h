#pragma once

#include "../../peripherals/peripheral_base.h"

#include <cstdint>
#include <mutex>

class Imx31Ipu : public Peripheral {
public:
    using Peripheral::Peripheral;

    bool ShouldRegister() override;
    void OnReady() override;

    uint32_t MmioBase() const override { return 0x53FC0000u; }
    uint32_t MmioSize() const override { return 0x00004000u; }

    uint32_t ReadWord (uint32_t addr) override;
    void     WriteWord(uint32_t addr, uint32_t value) override;

    enum class PfsKind { Unknown = 0, RgbPack = 4, Yuv422 = 6, Generic = 7 };

    struct ChannelFormat {
        PfsKind  pfs       = PfsKind::Unknown;
        uint8_t  bpp_bits  = 0;
        uint16_t stride    = 0;
        uint8_t  wid[4]    = {};
        uint8_t  ofs[4]    = {};
        uint16_t fw        = 0;
        uint16_t fh        = 0;
    };

    bool          IsEnabled()        const;
    uint32_t      GetGuestW()        const;
    uint32_t      GetGuestH()        const;
    uint32_t      GetSdcBgFbPa()     const;
    ChannelFormat GetSdcBgFormat()   const;

    /* Bootloader-style one-shot bring-up: point the SDC bg channel at fb_pa as
       w x h RGB565 and enable SDC scan-out. The OS display driver later
       reprograms the same registers over MMIO. */
    void SetupSdcScanout(uint32_t fb_pa, uint32_t w, uint32_t h);

    void OnHostTick();

private:
    static constexpr uint32_t kRegCount       = 112u;
    static constexpr uint32_t kLastOff        = 0x1BCu;
    static constexpr uint32_t kCpmRows        = 128u;
    static constexpr uint32_t kCpmDwordsPerRow= 5u;
    static constexpr uint32_t kCpmDwordCount  = kCpmRows * kCpmDwordsPerRow;

    mutable std::mutex state_mtx_;
    uint32_t regs_[kRegCount] = {};

    uint32_t cpm_[kCpmDwordCount] = {};
    uint8_t  ima_mem_nu_   = 0;
    uint16_t ima_row_nu_   = 0;
    uint8_t  ima_word_nu_  = 0;
    uint32_t last_pub_w_   = 0;
    uint32_t last_pub_h_   = 0;

    void     ApplyResetsLocked();
    uint32_t ReadRegLocked (uint32_t off) const;
    void     WriteRegLocked(uint32_t off, uint32_t value);
    void     OnIpuConfWriteLocked(uint32_t old_conf, uint32_t new_conf);
    void     OnImaAddrWriteLocked(uint32_t value);
    void     OnImaDataWriteLocked(uint32_t value);
    void     PublishSdcDimsLocked();
    void     EffectiveDimsLocked(uint32_t* w, uint32_t* h) const;
    void     RouteSdc3VsyncToAvicLocked();

    static bool OffsetToSlot(uint32_t off, uint32_t* slot_out) {
        if (off > kLastOff || (off & 0x3u) != 0u) return false;
        *slot_out = off / 4u;
        return true;
    }

    static uint32_t ExtractBitsFromWord1(const uint32_t* w1_dwords,
                                         uint32_t lsb,
                                         uint32_t width);
    ChannelFormat   DecodeChannelFormatLocked(uint32_t channel) const;
};
