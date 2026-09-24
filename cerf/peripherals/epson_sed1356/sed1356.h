#pragma once

#include "../peripheral_base.h"
#include "../../lcd/display_mode_latch.h"
#include "sed1356_bitblt.h"

#include <chrono>
#include <cstdint>
#include <unordered_set>
#include <vector>

/* EPSON SED1356 / S1D13506 / S1D13806 Color LCD/CRT/TV Controller (Technical
   Manual X25B-A-001-12). Per-board base / buffer size / product code via
   Sed1356Config (Jornada 720 SED1356; NEC MobilePro 900 S1D13806). */
class Sed1356 : public Peripheral {
public:
    using Peripheral::Peripheral;

    bool ShouldRegister() override;
    void OnReady() override;

    uint32_t MmioBase() const override { return mmio_base_; }
    uint32_t MmioSize() const override { return 0x00400000u; }

    uint8_t  ReadByte (uint32_t addr) override;
    uint16_t ReadHalf (uint32_t addr) override;
    uint32_t ReadWord (uint32_t addr) override;
    void     WriteByte(uint32_t addr, uint8_t  value) override;
    void     WriteHalf(uint32_t addr, uint16_t value) override;
    void     WriteWord(uint32_t addr, uint32_t value) override;

    /* --- Display pipe state consumed by Sed1356Renderer (all §8.3). --- */
    bool     LcdDisplayOn() const;       /* REG[1FCh] bits 2:0 selects LCD.   */
    bool     LcdBlanked()   const { return (Reg(0x40) & 0x80u) != 0; }
    uint32_t LcdBpp()       const;       /* REG[040h] bits 2:0 -> 4/8/15/16.  */
    uint32_t LcdGuestW()    const { return ((Reg(0x32) & 0x7Fu) + 1u) * 8u; }
    uint32_t LcdGuestH()    const {
        return (((Reg(0x39) & 0x3u) << 8 | Reg(0x38)) & 0x3FFu) + 1u;
    }
    uint32_t LcdStartByte() const {      /* word address * 2 (§8.3.7 note).   */
        return ((Reg(0x44) & 0xFu) << 16 | Reg(0x43) << 8 | Reg(0x42)) * 2u;
    }
    uint32_t LcdStrideBytes() const {    /* 11-bit word offset (REG[046/047]). */
        return (((Reg(0x47) & 0x7u) << 8) | Reg(0x46)) * 2u;
    }
    uint32_t LcdPixelPan()  const { return Reg(0x48) & 0x3u; }
    uint32_t SwivelMode() const {        /* Table 8-19: 0/90/180/270 degrees. */
        return ((Reg(0x40) >> 4) & 1u) << 1 | ((Reg(0x1FC) >> 6) & 1u);
    }
    /* LCD LUT entry, 4-bit DAC components (§8.3.13). */
    void     LcdLutRgb(uint32_t index, uint8_t& r4, uint8_t& g4, uint8_t& b4) const;

    /* Ink/cursor layer (§8.3.10, §14). */
    uint32_t LcdInkCursorMode() const { return Reg(0x70) & 0x3u; }  /* 0 off, 1 cursor, 2 ink. */
    uint32_t LcdInkCursorStartByte() const;   /* Table 14-1 decode, bytes into VRAM. */
    uint32_t LcdCursorX() const { return ((Reg(0x73) & 0x3u) << 8) | Reg(0x72); }
    uint32_t LcdCursorY() const { return ((Reg(0x75) & 0x3u) << 8) | Reg(0x74); }
    bool     LcdCursorXNeg() const { return (Reg(0x73) & 0x80u) != 0; }
    bool     LcdCursorYNeg() const { return (Reg(0x75) & 0x80u) != 0; }
    /* Ink/cursor colors 0/1 as 5:6:5 components (REG[076h..07Ch]). */
    void     LcdInkColor(uint32_t which, uint8_t& r5, uint8_t& g6, uint8_t& b5) const;

    void SaveState(StateWriter& w) override;
    void RestoreState(StateReader& r) override;

    /* --- BitBLT engine surface (regs §8.3.12, latched by Sed1356BitBlt). --- */
    uint8_t  BltReg(uint32_t off) const { return Reg(off); }
    uint8_t* VramData()       { return vram_.data(); }
    uint32_t VramSize() const { return vram_size_; }
    /* Fold a display-buffer offset into the populated buffer: the 2 MB
       aperture aliases it (TM X25B-A-001 §10) - mask if power-of-2, else mod. */
    uint32_t VramWrap(uint32_t off) const {
        return vram_mask_ ? (off & vram_mask_) : (off % vram_size_);
    }
    uint32_t VramLoad(uint32_t off, uint32_t width) const;
    void     VramStore(uint32_t off, uint32_t value, uint32_t width);

private:
    static constexpr uint32_t kRegWindow      = 0x200u;
    static constexpr uint32_t kMediaPlugBase  = 0x1000u;
    static constexpr uint32_t kMediaPlugEnd   = 0x100Au;
    static constexpr uint32_t kBltAperture    = 0x100000u;
    static constexpr uint32_t kBltApertureEnd = 0x200000u;
    static constexpr uint32_t kVramBase       = 0x200000u;
    static constexpr uint32_t kVramAperture   = 0x200000u;

    uint8_t  Reg(uint32_t off) const { return reg_[off]; }
    uint8_t  RegRead (uint32_t off);
    void     RegWrite(uint32_t off, uint8_t value);
    uint8_t  ReadLutData();
    void     WriteLutData(uint8_t value);
    void     StepLutPointer();
    uint8_t  VndStatusBit() const;
    void     PublishOnLcdEnableEdge();

    uint8_t reg_[kRegWindow] = {};
    std::vector<uint8_t> vram_;

    uint32_t mmio_base_        = 0;
    uint32_t vram_size_        = 0;
    uint32_t vram_mask_        = 0;   /* size-1 if power-of-2, else 0 (use mod). */
    uint8_t  product_rev_code_ = 0;

    /* Two 256-entry RGB LUTs of 4-bit components (§8.3.13: LCD + CRT/TV).
       lut_rgb_latch_ holds R,G written before the committing B write. */
    uint8_t lcd_lut_[256][3] = {};
    uint8_t crt_lut_[256][3] = {};
    uint8_t lut_index_     = 0;   /* entry pointer (REG[1E2h] write resets). */
    uint8_t lut_component_ = 0;   /* 0=R 1=G 2=B, auto-increments (§8.3.13). */
    uint8_t lut_rgb_latch_[2] = {};

    DisplayModeLatch mode_latch_;

    /* Offsets whose dropped-write was already logged: log each undocumented
       register once (--log=Periph-recoverable in the field), never per-write. */
    std::unordered_set<uint32_t> dropped_logged_;

    std::chrono::steady_clock::time_point boot_time_{};

    Sed1356BitBlt blt_{*this};

    friend class Sed1356BitBlt;
};
