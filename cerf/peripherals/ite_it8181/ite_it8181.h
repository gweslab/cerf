#pragma once

#include "../peripheral_base.h"

#include "../../lcd/display_size_latch.h"

#include <cstdint>
#include <vector>

/* ITE IT8181 VGA/LCD controller (NetBSD hpcmips ite8181reg.h; guest ddi.dll). */
class IteIt8181 : public Peripheral {
public:
    using Peripheral::Peripheral;

    bool ShouldRegister() override;
    void OnReady() override;

    uint32_t MmioBase() const override { return kLcdCsBase; }
    uint32_t MmioSize() const override { return kLcdCsSize; }

    uint8_t  ReadByte (uint32_t addr) override;
    uint16_t ReadHalf (uint32_t addr) override;
    uint32_t ReadWord (uint32_t addr) override;
    void     WriteByte(uint32_t addr, uint8_t  value) override;
    void     WriteHalf(uint32_t addr, uint16_t value) override;
    void     WriteWord(uint32_t addr, uint32_t value) override;

    void SaveState(StateWriter& w) override;
    void RestoreState(StateReader& r) override;

    bool     IsEnabled() const { return fb_written_; }
    uint32_t GuestW()    const { return kSplashW; }
    uint32_t GuestH()    const { return kSplashH; }
    uint32_t Bpp()       const { return kSplashBpp; }
    uint32_t StrideBytes() const { return kSplashStride; }
    const uint8_t* FbBytes() const { return fb_.data(); }

private:
    static constexpr uint32_t kLcdCsBase = 0x0A000000u;
    static constexpr uint32_t kLcdCsSize = 0x00800000u;
    static constexpr uint32_t kVramSize  = 0x00080000u;

    /* Splash geometry is bootloader-seeded (no register carries it at splash);
       nk.exe sub_9F003660 blits 640x240 2bpp at a 256-byte line pitch. */
    static constexpr uint32_t kSplashW      = 640u;
    static constexpr uint32_t kSplashH      = 240u;
    static constexpr uint32_t kSplashBpp    = 2u;
    static constexpr uint32_t kSplashStride = 256u;

    void PublishScreenSizeOnWriteEdge();

    std::vector<uint8_t> fb_;
    bool     fb_written_      = false;
    DisplaySizeLatch size_latch_;
};
