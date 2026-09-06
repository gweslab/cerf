#pragma once

#include "../../peripherals/peripheral_base.h"

#include "../../lcd/display_size_latch.h"

#include <cstdint>
#include <mutex>
#include <vector>

/* Casio multifunction ASIC in the "LCD/High-Speed System Bus Area
   0x0A000000-0x0AFFFFFF" (VR4121 UM Figure 6-8). Registers from nk.exe StartUp
   0x9F0B5BC4, sub_9F0B6E78, sub_9F0B7D20, sub_9F0B7DE0, ISR 0x9F0BA2C4, and the
   pcmcia.dll card-controller sub_1355CF0 / sub_1355C3C. */
class CasioToricomailAsic : public Peripheral {
public:
    using Peripheral::Peripheral;

    bool ShouldRegister() override;
    void OnReady() override;

    uint32_t MmioBase() const override { return kBase; }
    uint32_t MmioSize() const override { return kWindowSize; }

    uint8_t  ReadByte (uint32_t addr) override;
    uint16_t ReadHalf (uint32_t addr) override;
    uint32_t ReadWord (uint32_t addr) override;
    void     WriteByte(uint32_t addr, uint8_t  value) override;
    void     WriteHalf(uint32_t addr, uint16_t value) override;
    void     WriteWord(uint32_t addr, uint32_t value) override;

    void SaveState(StateWriter& w) override;
    void RestoreState(StateReader& r) override;
    void PostRestore() override;

    /* keybddr.dll side-button IST (SYSINTR 16): mask = ASIC 0x1004 line bit; a 0xE2
       line (0x1004 sub_1361FA0 / sub_1361CD8) drives the ASIC interrupt output. */
    void SetSideButton(uint16_t mask, bool pressed);

    /* ddi.dll sub_1380C50/sub_1381C54 enable the panel with 0xA02 |= 1 / 0xA00 &= ~1;
       nk.exe power-down sub_9F0B8720 disables it with 0xA00 = 1. */
    bool IsDisplayEnabled() const { return (reg_0A02_ & 1u) && !(reg_0A00_ & 1u); }
    uint32_t GuestW()      const { return kVisibleW; }
    uint32_t GuestH()      const { return kVisibleH; }
    uint32_t StrideBytes() const { return kPitchBytes; }
    uint32_t FbPa()        const { return kBase + kFbOffset; }
    const uint8_t* FbBytes() const { return fb_.data(); }

private:
    /* nk.exe sub_9F0B7DE0: pixel at 2*(x + (y<<9)) + 0xAA200000, row advance -2*w + 1024
       => framebuffer PA 0x0A200000, 1024-byte pitch (512 px), 16bpp. */
    static constexpr uint32_t kBase       = 0x0A000000u;
    static constexpr uint32_t kWindowSize = 0x01000000u;
    static constexpr uint32_t kFbOffset   = 0x00200000u;
    static constexpr uint32_t kFbSize     = 0x00040000u;
    static constexpr uint32_t kPitchBytes = 1024u;
    static constexpr uint32_t kVisibleW   = 320u;
    static constexpr uint32_t kVisibleH   = 240u;
    /* casio_toricomail_ce212 ddi.dll sub_13810E4 @0x13810E4 stages the 1bpp mask in 16-row
       bands, re-seeding the row pointer per band by 2*((320*(y>>4))>>4) bytes. */
    static constexpr uint32_t kStageBandBytes = 40u;
    static uint32_t StageOffset(uint32_t y) {
        return (y >> 4) * kStageBandBytes + (y & 15u) * kPitchBytes;
    }

    bool     InFb(uint32_t off) const { return off >= kFbOffset && off < kFbOffset + kFbSize; }
    uint16_t ReadReg(uint32_t off);
    void     WriteReg(uint32_t off, uint16_t value);
    void     RunFillLocked();
    void     RunBlitLocked();
    void     RunBlit7Locked();
    void     MaybePublishDisplaySize();
    void     UpdateSideButtonInterruptLocked();

    /* nk.exe ISR 0x9F0BA2C4 gates the ASIC interrupt on (0x1008 & 0x100A) & 0xE2;
       its output is GIU pin 9 (GIUINTSTATL bit9, cleared by writing 0x200 to
       0xAB000108). GIU pin 9 is level/active-low (sub_9F0B9754: GIUINTTYPL bit9=0,
       GIUINTALSELL bit9=0, GIUINTENL bit9=1), so an asserted interrupt drives it low. */
    static constexpr uint16_t kSideBtnIntMask = 0xE2u;
    static constexpr int      kSideBtnGiuPin  = 9;

    std::vector<uint8_t> fb_;

    /* Blit/fill engine. nk.exe fill sub_9F0B7D20 writes 0x200=0/0x202=color/0x204=320/
       0x206=240 then triggers 0x21A; ddi.dll blit sub_13815A8 writes 0x202 color,
       (h<<16)+w at 0x204/0x206, a 32-bit destination byte-offset at 0x208/0x20A, then
       triggers 0x21A (poll bit0 busy). */
    uint16_t fill_value_  = 0;
    uint16_t fill_width_  = 0;
    uint16_t fill_height_ = 0;
    uint16_t fill_dst_lo_ = 0;
    uint16_t fill_dst_hi_ = 0;

    /* casio_toricomail_ce212 ddi.dll sub_13810E4 @0x13810E4: 0x200 low = 2 selects the mono
       expand (fill = 0); 0x210/0x212 = 32-bit staged source byte-offset; 0x214 = the signed
       srcX&7 source bit offset. */
    uint16_t fill_src_lo_ = 0;
    uint16_t fill_src_hi_ = 0;
    uint16_t blit_src_bit_ = 0;
    uint16_t blit_mode_   = 0;

    /* ddi.dll 16bpp copy sub_13812F8 drives a second blit engine at 0x700: 0x700 trigger
       (bit0 busy), 0x704 width, 0x706 height, 0x708 32-bit source kseg1 address (a DRAM
       staging buffer), 0x70C 32-bit destination framebuffer offset. */
    uint16_t blit7_ctl_    = 0;
    uint16_t blit7_width_  = 0;
    uint16_t blit7_height_ = 0;
    uint16_t blit7_src_lo_ = 0;
    uint16_t blit7_src_hi_ = 0;
    uint16_t blit7_dst_lo_ = 0;
    uint16_t blit7_dst_hi_ = 0;

    /* nk.exe ISR 0x9F0BA2C4: interrupt STATUS 0x1008 / ENABLE 0x100A / 0x100C; causes 0xE2
       drive GIU pin 9 (SYSINTR 16). No modeled source raises a cause yet. */
    uint16_t int_status_ = 0;
    uint16_t int_enable_ = 0;

    /* keybddr.dll scan sub_1361FA0 reads ASIC 0x1004 (dword_1365130+4) as the side-button
       status: bits {1,2,5,6,7} pressed (dispatch sub_1361CD8 -> VK table dword_13604F0
       "df 00 00 00 79": bit2->VK 0xDF, bit1->VK 0x79, bits5/6/7 interrupt-only). */
    uint16_t side_buttons_ = 0;

    std::mutex int_mtx_;
    bool       side_btn_int_asserted_ = false;

    /* nk.exe sub_9F0B9890 (ASIC re-init) RMWs 0x1120 |= 8 (bit3, read 0x9F0B989C / write
       0x9F0B98A8); ISR sub_9F0B991C @0x9F0B9A14 reads bit0 (wake-status, PMUINTREG-gated). */
    uint16_t reg_1120_ = 0;

    /* serial.dll sub_1332BB0 RMWs bit3 of 0x1000 + 0x1002 (0x1002 read @0x1332BD4, lh);
       nk.exe sub_9F0B8720 power-down also writes 0x1000. */
    uint16_t reg_1000_ = 0;
    /* StartUp (0x9F0B5BCC) 0x1002=0x108, 0x1010=3, 0x1134=0; display-init sub_9F0B6E78
       0x7A2/0x7A4/0x7A0, 0x40A posted-write flush, 0x406 3-wire DAC (RMW'd by power-down). */
    uint16_t reg_1002_ = 0;
    uint16_t reg_1010_ = 0;
    uint16_t reg_1134_ = 0;
    uint16_t reg_7a0_  = 0;
    uint16_t reg_7a2_  = 0;
    uint16_t reg_7a4_  = 0;
    uint16_t reg_40a_  = 0;
    uint16_t reg_406_  = 0;

    /* nk.exe sub_9F0B8720 suspend: reads 0x010-0x01E; RMW 0x1130. */
    uint16_t suspend_save_[8] = {};
    uint16_t reg_1130_ = 0;

    /* ASIC 0x1118/0x111A deadman SW-reset arm state (WriteReg). */
    bool dms_armed_ = true;

    /* Display-enable control pair: ddi.dll sub_1380C50/sub_1381C54 RMW bit0 of 0xA00 (&=~1)
       and 0xA02 (|=1); nk.exe power-down sub_9F0B8720 writes 0xA00=1. Stored R/W. */
    uint16_t reg_0A00_ = 0;
    uint16_t reg_0A02_ = 0;
    DisplaySizeLatch size_latch_;

    /* pcmcia.dll card-controller socket-init sub_1355CF0 / deinit sub_1355DC4:
       0x920 |= 3; 0x922 |= 1, |= 2, = 0; 0x1112 |= 1, &= ~1. */
    uint16_t reg_0920_ = 0;
    uint16_t reg_0922_ = 0;
    uint16_t reg_1112_ = 0;

    /* socket.dll (modem-socket driver) control register 0xB00: start @0x1300D94 reads it
       (discarded) before the ISR thread; sub_1301008 RMWs it (& 0xE0F8). Stored R/W. */
    uint16_t reg_0B00_ = 0;

    /* socket.dll control register 0xB10: sub_1301008 RMWs it (& 0xE0F0) with 0xB00 on the
       socket-open path (ModemSockOpenDevice -> sub_1300F04 -> sub_1301008). Stored R/W. */
    uint16_t reg_0B10_ = 0;

    /* 0xB02 socket interrupt-enable/mask: nk.exe OEMInterruptEnable sub_9F0DF940 RMW-sets
       the socket SYSINTR 30 / 28 enable bits (|= 0x100 / 0x400). Stored R/W. */
    uint16_t reg_0B02_ = 0;

    /* serial.dll RMWs bit0 of 0xB1E (|=1 open: sub_1331128/sub_1331DE0; &=~1 close:
       sub_1331FE0 read @0x133222C / sub_1331D20). */
    uint16_t reg_0B1E_ = 0;
};
