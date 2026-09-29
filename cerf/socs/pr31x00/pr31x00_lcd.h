#pragma once

#include "../raster_scan_peripheral.h"

#include <cstdint>

class Pr31x00Clock;
class Pr31x00Intc;

/* Philips PR31x00 Video Module, TMPR3911/3912 ch.17. Registers $028-$05C. */
class Pr31x00Lcd : public RasterScanPeripheral {
public:
    using RasterScanPeripheral::RasterScanPeripheral;

    bool ShouldRegister() override;
    void OnReady() override;

    uint32_t MmioBase() const override { return 0x10C00028u; }
    uint32_t MmioSize() const override { return 0x38u; }   /* $028-$05F */

    uint32_t ReadWord(uint32_t addr) override;
    void     WriteWord(uint32_t addr, uint32_t value) override;

    uint8_t  ReadByte(uint32_t addr) override { HaltUnsupportedAccess("PR31x00 LCD ReadByte", addr, 0); }
    uint16_t ReadHalf(uint32_t addr) override { HaltUnsupportedAccess("PR31x00 LCD ReadHalf", addr, 0); }
    void WriteByte(uint32_t addr, uint8_t  v) override { HaltUnsupportedAccess("PR31x00 LCD WriteByte", addr, v); }
    void WriteHalf(uint32_t addr, uint16_t v) override { HaltUnsupportedAccess("PR31x00 LCD WriteHalf", addr, v); }

    /* Consumed by Pr31x00LcdRenderer. */
    bool     IsEnabled() const;
    bool     IsInverted() const;
    uint32_t GetFbPa() const;
    uint32_t GetGuestW() const;
    uint32_t GetGuestH() const;
    uint32_t GetBitsPerPixel() const;

    /* Maps a raw pixel value to its 4-bit gray shade. 4-bit gray needs no LUT;
       2-bit gray selects one of four BLUESEL nibbles (§17.3.7). */
    uint32_t ShadeFor(uint32_t raw) const;

    void SaveState(StateWriter& w) override;
    void RestoreState(StateReader& r) override;
    void PostRestore() override;

protected:
    ScanShape              ScanShapeLocked() const override;
    RasterScanClock::Frame ScanFrameLocked() const;
    void                   FrameEdgeLocked(uint32_t edge_index) override;
    void                   ScanEdgesRan() override;

private:
    void StorePattern(uint32_t idx, uint32_t addr, uint32_t value,
                      uint32_t recommended, const char* op);
    void     WriteRegLocked(uint32_t addr, uint32_t value, uint64_t now);
    bool     ScanWantedLocked() const;
    void     SyncScanLocked(uint64_t now);
    uint32_t LineCntLocked(uint64_t now) const;

    static constexpr uint32_t kRegs = 14;   /* VIDEO_CTL1..CTL14 */

    uint32_t reg_[kRegs] = {};

    Pr31x00Intc*  intc_  = nullptr;
    Pr31x00Clock* clock_ = nullptr;

    uint32_t held_linecnt_       = 0;
    bool     frame_edge_pending_ = false;
    bool     enabled_edge_       = false;
    bool     cp_rate_changed_    = false;
};
