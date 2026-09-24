#pragma once

#include "../peripheral_base.h"
#include "../../lcd/display_mode_latch.h"
#include "mediaq_mq200_ge.h"

#include <cstdint>
#include <vector>

/* MediaQ MQ200 display controller (SA-1110 boards: SIMpad SL4, SmartBook G138).
   MmioBase 0x4B800000 = 2 MB framebuffer SRAM at window offset 0; the register
   block (PA 0x4BE00000) is at offset 0x600000; display geometry is Graphics
   Controller 1 at register offset 0xA000 (MQ-200 Data Book Table 5-3). */
class MediaQMq200 : public Peripheral, public MediaQGeHost {
public:
    using Peripheral::Peripheral;

    bool ShouldRegister() override;
    void OnReady() override;

    uint32_t MmioBase() const override { return 0x4B800000u; }
    uint32_t MmioSize() const override { return kRegWinOff + kRegSize; }

    uint8_t  ReadByte (uint32_t addr) override;
    uint16_t ReadHalf (uint32_t addr) override;
    uint32_t ReadWord (uint32_t addr) override;
    void     WriteByte(uint32_t addr, uint8_t  value) override;
    void     WriteHalf(uint32_t addr, uint16_t value) override;
    void     WriteWord(uint32_t addr, uint32_t value) override;

    void SaveState(StateWriter& w) override;
    void RestoreState(StateReader& r) override;

    /* Display-state getters consumed by MediaQMq200Renderer, read from the
       Graphics Controller that FP00R[1:0] selects to drive the flat panel. */
    bool     IsEnabled()      const;   /* panel GC control[3] image window on + valid mode. */
    uint32_t Bpp()            const;   /* panel GC control[7:4] depth (Table 5-8). */
    uint32_t GetGuestW()      const;   /* panel GC H-window[31:16] + 1. */
    uint32_t GetGuestH()      const;   /* panel GC V-window[31:16] + 1. */
    uint32_t FbWindowOffset() const;   /* panel GC start[20:0], byte offset in FB SRAM. */
    uint32_t Stride()         const;   /* panel GC stride[15:0], bytes per scanline. */
    uint32_t PaletteEntry(uint32_t index) const;   /* C100R+i: R[7:0] G[15:8] B[23:16]. */
    const uint8_t* FbBytes()  const { return fb_.data(); }
    uint8_t*       FbMutableBytes() override { return fb_.data(); }   /* GE blit target. */
    uint32_t       FbSize()   const override { return kFbSize; }

private:
    static constexpr uint32_t kFbSize    = 0x200000u;   /* sub_134BAA8 a1[65] */
    static constexpr uint32_t kRegWinOff = 0x600000u;   /* register block window offset */
    static constexpr uint32_t kRegSize   = 0x1A000u;    /* sub_134BAA8 a1[66] */

    /* PCI-config block (Table 5-3 @ 0x16000): ID gate + idle poll. */
    static constexpr uint32_t kRegId    = 0x16000u;     /* ID gate: == 0x02004D51 ("MQ"). */
    static constexpr uint32_t kRegIdle  = 0x16044u;     /* status; mode-set spins while [1:0] != 0. */
    static constexpr uint32_t kDeviceId = 0x02004D51u;

    /* CIF (Table 5-3 @ 0x2000) CC01R index 0x04 = Source/Command FIFO/GE Status
       (Data Book Table 5-86); ddi.dll busy-waits on it around each blit. The
       engine answers via MediaQMq200Ge::StatusReady(). */
    static constexpr uint32_t kRegGeStatus = 0x2004u;

    /* Graphics Engine (Table 5-3 @ 0xC000) register block + Source FIFO port. */
    static constexpr uint32_t kGeBlockLo = 0xC000u;
    static constexpr uint32_t kGeBlockHi = 0xC200u;
    static constexpr uint32_t kSrcFifo   = 0x18000u;

    /* Two Graphics Controllers, GC1 @ 0x0A000 and GC2 @ 0x0A080 (identical
       layout, GC2 = GC1 + 0x80; Data Book Table 5-3). FP00R[1:0] (Flat Panel
       Control, Table 5-51) picks which drives the flat panel: 01=GC1, 11=GC2,
       x0=off. (SIMpad SL4 panel = GC1; SmartBook G138 panel = GC2, GC1 = CRT.) */
    static constexpr uint32_t kGc1Base  = 0xA000u;
    static constexpr uint32_t kGc2Base  = 0xA080u;
    static constexpr uint32_t kGcCtrl   = 0x00u;   /* [0] ctrl-en, [3] img-win-en, [7:4] depth. */
    static constexpr uint32_t kGcHWin   = 0x20u;   /* [31:16] = width - 1. */
    static constexpr uint32_t kGcVWin   = 0x24u;   /* [31:16] = height - 1. */
    static constexpr uint32_t kGcStart  = 0x30u;   /* window start address [20:0]. */
    static constexpr uint32_t kGcStride = 0x38u;   /* window stride [15:0]. */
    static constexpr uint32_t kGc00ImgWinEnable = 0x8u;    /* control[3] (Table 5-8). */
    static constexpr uint32_t kFp00R        = 0xE000u;     /* Flat Panel Control (Table 5-51). */
    static constexpr uint32_t kFpEnable     = 0x1u;        /* FP00R[0]: interface enable. */
    static constexpr uint32_t kFpDriveCtrl2 = 0x2u;        /* FP00R[1]: 0=GC1, 1=GC2. */

    static constexpr uint32_t kPaletteBase = 0x10000u;   /* Color Palette 1 (Table 5-3). */

    uint32_t Reg(uint32_t roff) const { return reg_[roff / 4u]; }
    uint32_t PanelGcBase() const;   /* 0xA000/0xA080, or 0 when no panel controller is enabled. */
    uint32_t RegRead(uint32_t roff);
    void     RegWrite(uint32_t roff, uint32_t value);
    void     PublishScreenSizeOnEnableEdge();

    std::vector<uint8_t>  fb_;
    std::vector<uint32_t> reg_;
    DisplayModeLatch mode_latch_;
    MediaQMq200Ge ge_{*this};
};
