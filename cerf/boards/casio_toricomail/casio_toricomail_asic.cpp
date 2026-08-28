#include "casio_toricomail_asic.h"

#include "../../boards/board_context.h"
#include "../../core/cerf_emulator.h"
#include "../../core/fatal.h"
#include "../../core/log.h"
#include "../../cpu/emulated_memory.h"
#include "../../peripherals/peripheral_dispatcher.h"
#include "../../socs/guest_cpu_reset.h"
#include "../../socs/vr41xx/vr41xx_giu.h"
#include "../../state/emulation_freeze.h"
#include "../../state/state_stream.h"

#include <cstring>
#include <mutex>

bool CasioToricomailAsic::ShouldRegister() {
    auto* bd = emu_.TryGet<BoardContext>();
    return bd && bd->GetBoard() == Board::CasioToricomail;
}

void CasioToricomailAsic::OnReady() {
    fb_.assign(kFbSize, 0u);
    emu_.Get<PeripheralDispatcher>().Register(this);
}

/* nk.exe fill sub_9F0B7D20 (whole 320x240) and ddi.dll blit sub_13815A8 (arbitrary
   rectangle at the 0x208/0x20A dst byte-offset) fill fill_width_ x fill_height_ 16-bit
   pixels of fill_value_ into the framebuffer at the 1024-byte pitch. */
void CasioToricomailAsic::RunFillLocked() {
    if (fill_width_ == 0 || fill_height_ == 0) return;
    const uint32_t dst = static_cast<uint32_t>(fill_dst_lo_) |
                         (static_cast<uint32_t>(fill_dst_hi_) << 16);
    const uint64_t last = static_cast<uint64_t>(dst) +
                          static_cast<uint64_t>(fill_height_ - 1u) * kPitchBytes +
                          static_cast<uint64_t>(fill_width_) * 2u;
    if (last > kFbSize) {
        LOG(Caution, "CasioToricomailAsic: fill dst=0x%X w=%u h=%u exceeds framebuffer\n",
            dst, fill_width_, fill_height_);
        CerfFatalExit(CERF_FATAL_RUNTIME_ERROR);
    }
    for (uint32_t y = 0; y < fill_height_; ++y) {
        uint8_t* row = fb_.data() + dst + static_cast<size_t>(y) * kPitchBytes;
        for (uint32_t x = 0; x < fill_width_; ++x)
            std::memcpy(row + x * 2u, &fill_value_, sizeof(fill_value_));
    }
    /* ddi.dll blit sub_13815A8 writes 0x208/0x20A fresh on every blit; nk.exe fill
       sub_9F0B7D20 never writes them and fills from origin - the destination is
       per-operation (VR4121 Casio ASIC, no datasheet; reconciled from both drivers). */
    fill_dst_lo_ = 0;
    fill_dst_hi_ = 0;
}

/* 0x200 low selects the operation: nk.exe fill sub_9F0B7D20 / ddi.dll fill sub_13815A8
   write 0 (fill); ddi.dll text blit sub_13810E4 writes 2 (monochrome expand). */
void CasioToricomailAsic::RunBlitLocked() {
    if (blit_mode_ != 2u) { RunFillLocked(); return; }

    /* ddi.dll sub_138165C routes ROP 0xAAF0 (masked text) to sub_13810E4, which addresses
       its source as 1bpp (srcX>>3) and stages the glyph mask at 0x210/0x212; the engine
       expands the mask to 16bpp - 0x202 foreground colour on set bits, destination left on
       clear bits (ROP 0xAAF0 background = destination). 0x214 mask-mode 0 is the only form. */
    if (blit_rop_ != 0u) {
        LOG(Caution, "CasioToricomailAsic: text blit rop=0x%X not modeled\n", blit_rop_);
        CerfFatalExit(CERF_FATAL_RUNTIME_ERROR);
    }
    if (fill_width_ == 0 || fill_height_ == 0) return;
    const uint32_t dst = static_cast<uint32_t>(fill_dst_lo_) |
                         (static_cast<uint32_t>(fill_dst_hi_) << 16);
    const uint32_t src = static_cast<uint32_t>(fill_src_lo_) |
                         (static_cast<uint32_t>(fill_src_hi_) << 16);
    const uint32_t mask_bytes = (fill_width_ + 7u) / 8u;
    const uint64_t dst_span = static_cast<uint64_t>(fill_height_ - 1u) * kPitchBytes +
                              static_cast<uint64_t>(fill_width_) * 2u;
    const uint64_t src_span = static_cast<uint64_t>(fill_height_ - 1u) * kPitchBytes + mask_bytes;
    if (static_cast<uint64_t>(dst) + dst_span > kFbSize ||
        static_cast<uint64_t>(src) + src_span > kFbSize) {
        LOG(Caution, "CasioToricomailAsic: text blit dst=0x%X src=0x%X w=%u h=%u exceeds framebuffer\n",
            dst, src, fill_width_, fill_height_);
        CerfFatalExit(CERF_FATAL_RUNTIME_ERROR);
    }
    if (src < dst + dst_span && dst < src + src_span) {
        LOG(Caution, "CasioToricomailAsic: text blit overlapping dst=0x%X src=0x%X w=%u h=%u\n",
            dst, src, fill_width_, fill_height_);
        CerfFatalExit(CERF_FATAL_RUNTIME_ERROR);
    }
    const uint16_t fg = fill_value_;
    for (uint32_t y = 0; y < fill_height_; ++y) {
        const uint8_t* mask = fb_.data() + src + static_cast<size_t>(y) * kPitchBytes;
        uint8_t*       row  = fb_.data() + dst + static_cast<size_t>(y) * kPitchBytes;
        for (uint32_t x = 0; x < fill_width_; ++x)
            if ((mask[x >> 3] >> (7u - (x & 7u))) & 1u)
                std::memcpy(row + x * 2u, &fg, sizeof(fg));
    }
    fill_dst_lo_ = 0; fill_dst_hi_ = 0;
    fill_src_lo_ = 0; fill_src_hi_ = 0;
}

/* ddi.dll 16bpp copy sub_13812F8 stages each source row into a DRAM buffer, sets 0x708 to
   its kseg1 address, 0x70C to the destination framebuffer offset, 0x704 width, 0x706 height,
   then writes 0x700=1 to copy width x height 16bpp pixels DRAM -> framebuffer. */
void CasioToricomailAsic::RunBlit7Locked() {
    if (blit7_width_ == 0 || blit7_height_ == 0) return;
    /* ddi.dll sub_13812F8 writes 0x706=1 and stages one source row per trigger. */
    if (blit7_height_ != 1u) {
        LOG(Caution, "CasioToricomailAsic: 0x700 blit height=%u (only 1 grounded)\n",
            blit7_height_);
        CerfFatalExit(CERF_FATAL_RUNTIME_ERROR);
    }
    const uint32_t src_pa = (static_cast<uint32_t>(blit7_src_lo_) |
                             (static_cast<uint32_t>(blit7_src_hi_) << 16)) & 0x1FFFFFFFu;
    const uint32_t dst = static_cast<uint32_t>(blit7_dst_lo_) |
                         (static_cast<uint32_t>(blit7_dst_hi_) << 16);
    const uint32_t row_bytes = static_cast<uint32_t>(blit7_width_) * 2u;
    if (static_cast<uint64_t>(dst) + row_bytes > kFbSize) {
        LOG(Caution, "CasioToricomailAsic: 0x700 blit dst=0x%X w=%u exceeds framebuffer\n",
            dst, blit7_width_);
        CerfFatalExit(CERF_FATAL_RUNTIME_ERROR);
    }
    uint8_t* host_src = emu_.Get<EmulatedMemory>().TryTranslate(src_pa);
    if (!host_src) {
        LOG(Caution, "CasioToricomailAsic: 0x700 blit src_pa=0x%X unbacked\n", src_pa);
        CerfFatalExit(CERF_FATAL_RUNTIME_ERROR);
    }
    std::memcpy(fb_.data() + dst, host_src, row_bytes);
}

void CasioToricomailAsic::MaybePublishDisplaySize() {
    size_latch_.PublishOnce(emu_, IsDisplayEnabled());
}

void CasioToricomailAsic::SetSideButton(uint16_t mask, bool pressed) {
    auto frozen = emu_.Get<EmulationFreeze>().WorkerSection();
    std::lock_guard<std::mutex> lk(int_mtx_);
    if (pressed) side_buttons_ |= mask;
    else         side_buttons_ &= static_cast<uint16_t>(~mask);
    UpdateSideButtonInterruptLocked();
}

/* nk.exe ISR 0x9F0BA2C4: interrupt asserted (GIU pin 9 low) while a 0xE2 line is
   pressed (0x1004) AND armed (0x1008) AND enabled (0x100A). */
void CasioToricomailAsic::UpdateSideButtonInterruptLocked() {
    const bool asserted =
        (side_buttons_ & int_status_ & int_enable_ & kSideBtnIntMask) != 0;
    if (asserted == side_btn_int_asserted_) return;
    side_btn_int_asserted_ = asserted;
    emu_.Get<Vr41xxGiu>().SetPinLevel(kSideBtnGiuPin, !asserted);
}

uint16_t CasioToricomailAsic::ReadReg(uint32_t off) {
    switch (off) {
        /* nk.exe 0x9F0B70D4 reads 0x40A as a posted-write flush; sub_9F0B8720 RMWs 0x406
           (3-wire DAC). */
        case 0x40A: return reg_40a_;
        case 0x406: return reg_406_;
        /* sub_9F0B7D20 polls 0x218 / 0x21A bit0 until the fill (run in the write) clears it. */
        case 0x218: return 0;
        case 0x21A: return 0;
        /* ddi.dll copy sub_13812F8 polls 0x700 bit0 (busy) before each row trigger. */
        case 0x700: return 0;
        /* ISR 0x9F0BA2C4 reads STATUS 0x1008 and ENABLE 0x100A. */
        case 0x1008: { std::lock_guard<std::mutex> lk(int_mtx_); return int_status_; }
        case 0x100A: { std::lock_guard<std::mutex> lk(int_mtx_); return int_enable_; }
        /* keybddr.dll scan sub_1361FA0 reads 0x1004 (dword_1365130+4) as side-button status. */
        case 0x1004: { std::lock_guard<std::mutex> lk(int_mtx_); return side_buttons_; }
        /* sub_9F0B8720 reads 0x1134 bit0 (reboot vs HIBERNATE). */
        case 0x1134: return reg_1134_;
        /* serial.dll sub_1332BB0 RMWs bit3 of 0x1000 (@0x1332BE8) and 0x1002 (@0x1332BD4). */
        case 0x1000: return reg_1000_;
        case 0x1002: return reg_1002_;
        /* wavedev.dll sub_1341CB8 (|=2) / sub_1341694 (|=1) RMW 0x1010 (nk.exe StartUp writes 3). */
        case 0x1010: return reg_1010_;
        /* sub_9F0B9890 RMW 0x1120 |= 8; sub_9F0B991C @0x9F0B9A14 reads bit0. */
        case 0x1120: return reg_1120_;
        /* Battery-health status bit0: ddi.dll sub_1381FD0/sub_1381FFC read it (0->BrightExPower,
           1->BrightBattery); nk.exe sub_9F0B61DC @0x9F0B63C8 halts on no-AC + bit0 set. bit0=0=healthy. */
        case 0x1122: return 0;
        /* sub_9F0B8720 saves 0x010-0x01E to DRAM at suspend; RMW's 0x1130 (|=2 then &=~2). */
        case 0x010: case 0x012: case 0x014: case 0x016:
        case 0x018: case 0x01A: case 0x01C: case 0x01E:
            return suspend_save_[(off - 0x010u) / 2u];
        case 0x1130: return reg_1130_;
        /* ddi.dll sub_1380C50/sub_1381C54 RMW bit0 of 0xA00 (&=~1) + 0xA02 (|=1) at display-enable. */
        case 0xA00: return reg_0A00_;
        case 0xA02: return reg_0A02_;
        /* pcmcia.dll card-controller socket-init sub_1355CF0 RMWs 0x920/0x922/0x1112. */
        case 0x920:  return reg_0920_;
        case 0x922:  return reg_0922_;
        case 0x1112: return reg_1112_;
        /* pcmcia.dll sub_1355C3C polls 0x900 bit0 (busy) with a 0x1F5-tick timeout. */
        case 0x900:  return 0;
        /* pcmcia.dll sub_1355BD0 polls 0x912 bit15 (data-ready); sub_1355B00 reads 0x906. */
        case 0x912:  return 0;
        /* socket.dll start @0x1300D94 reads 0xB00 (result discarded, pre-ISR-thread flush);
           sub_1301008 RMWs it (& 0xE0F8) as the socket-controller control register. */
        case 0xB00: return reg_0B00_;
        /* socket.dll sub_1301008 RMWs 0xB10 (& 0xE0F0) as the second socket control register. */
        case 0xB10: return reg_0B10_;
        /* nk.exe OEMInterruptEnable sub_9F0DF940 RMW-sets socket int-enable bits in 0xB02
           (case 30 |= 0x100 SYSINTR 30, case 28 |= 0x400 SYSINTR 28). */
        case 0xB02: return reg_0B02_;
        /* socket.dll (modem-socket driver) sub_1300FEC reads 0xB18[3:0] as socket status;
           sub_1300948 treats 7 as no-device (== 7 -> deregister only) and its static baseline
           dword_130183C / dword_1301848 init to 7, so 7 = empty socket (no state change). */
        case 0xB18: return 7;
        /* serial.dll RMWs bit0 of 0xB1E (read half @0x133222C in sub_1331FE0). */
        case 0xB1E: return reg_0B1E_;
        default:
            HaltUnsupportedAccess("Casio ASIC ReadReg", kBase + off, 0);
    }
}

void CasioToricomailAsic::WriteReg(uint32_t off, uint16_t value) {
    /* sub_9F0B6E78 panel-enable / display-latch. */
    if (off == 0x7A0 || off == 0x7A2) { (off == 0x7A0 ? reg_7a0_ : reg_7a2_) = value; return; }
    if (off == 0x7A4) { reg_7a4_ = value; return; }

    /* sub_9F0B6E78 writes timing/DAC/flush 0x400-0x410, grayscale 0x5E4, gamma 0x600-0x62C. */
    if (off == 0x40A) { reg_40a_ = value; return; }
    if (off == 0x406) { reg_406_ = value; return; }
    if (off >= 0x400 && off <= 0x410 && (off & 1) == 0) return;
    if (off == 0x5E4) return;
    if (off >= 0x600 && off <= 0x62C && (off & 1) == 0) return;

    /* sub_9F0B7D20 fill engine: dst 0x200, value 0x202, width 0x204, height 0x206;
       0x21C=1 / 0x21E=0 are the only config the callers write. */
    switch (off) {
        /* nk.exe fill sub_9F0B7D20 / ddi.dll fill sub_13815A8 write 0x200 low = 0 (fill);
           ddi.dll blit sub_13810E4 writes 0x200 low = 2 (copy). */
        case 0x200: if (value != 0u && value != 2u) break; blit_mode_ = value; return;
        case 0x202: fill_value_  = value; return;
        case 0x204: fill_width_  = value; return;
        case 0x206: fill_height_ = value; return;
        /* ddi.dll fill sub_13815A8 writes a 32-bit destination byte-offset at 0x208/0x20A;
           ddi.dll blit sub_13810E4 writes a 32-bit source at 0x210/0x212 and the ROP at 0x214. */
        case 0x208: fill_dst_lo_ = value; return;
        case 0x20A: fill_dst_hi_ = value; return;
        case 0x210: fill_src_lo_ = value; return;
        case 0x212: fill_src_hi_ = value; return;
        case 0x214: blit_rop_    = value; return;
        /* ddi.dll PDEV-enable sub_1380C50 @0x1380DA8 (and sub_1381C54 @0x1381D88) write 0x216=1. */
        case 0x216: if (value != 1u) break; return;
        case 0x218: if (value & 1u) RunBlitLocked(); return;
        case 0x21A: if (value & 1u) RunBlitLocked(); return;
        case 0x21C: if (value != 1u) break; return;
        case 0x21E: if (value != 0u) break; return;
        /* ddi.dll copy sub_13812F8: 0x702=0, 0x704 width, 0x706 height, 0x708/0x70A 32-bit
           source, 0x70C/0x70E 32-bit dest, 0x700=1 triggers the DRAM->framebuffer copy. */
        case 0x702: blit7_ctl_    = value; return;
        case 0x704: blit7_width_  = value; return;
        case 0x706: blit7_height_ = value; return;
        case 0x708: blit7_src_lo_ = value; return;
        case 0x70A: blit7_src_hi_ = value; return;
        case 0x70C: blit7_dst_lo_ = value; return;
        case 0x70E: blit7_dst_hi_ = value; return;
        case 0x700: if (value & 1u) RunBlit7Locked(); return;
        /* nk.exe ISR 0x9F0BA2C4 acks by writing 0x1008 &= 0xFF1D; OEMInterruptEnable
           sub_9F0DF940 case 16 sets 0x100A=0xFFFF, 0x1008|=0xE2. */
        case 0x1008: {
            std::lock_guard<std::mutex> lk(int_mtx_);
            int_status_ = value;
            UpdateSideButtonInterruptLocked();
            return;
        }
        case 0x100A: {
            std::lock_guard<std::mutex> lk(int_mtx_);
            int_enable_ = value;
            UpdateSideButtonInterruptLocked();
            return;
        }
        /* sub_9F0B9890 RMW 0x1120 |= 8; bit0 read on the resume path (sub_9F0B991C @0x9F0B9A14). */
        case 0x1120: reg_1120_ = value; return;
        /* sub_9F0B9890 writes 0x100C=0 (@0x9F0B98AC) and 0x00A=0xFFFF (@0x9F0B9900). */
        case 0x100C: return;
        case 0x00A:  return;
        /* serial.dll sub_1332BB0 RMW / nk.exe sub_9F0B8720 power-down write 0x1000. */
        case 0x1000: reg_1000_ = value; return;
        /* StartUp 0x9F0B5BCC: 0x1002=0x108, 0x1010=3, 0x1134=0. */
        case 0x1002: reg_1002_ = value; return;
        case 0x1010: reg_1010_ = value; return;
        case 0x1134: reg_1134_ = value; return;
        /* nk.exe IOCTL_HAL_REBOOT sub_9F0DF7AC + StartUp DMSRST branch 0x9F0B5ED0 write
           0x1118=0x0C then 0x111A=0x0A = the deadman software-reset trigger; the armed
           0x111A commit resets, StartUp's post-reset re-write finds it disarmed + re-arms. */
        case 0x1118:
            if (value != 0x0Cu) break;
            return;
        case 0x111A:
            if (value != 0x0Au) break;
            if (dms_armed_) {
                dms_armed_ = false;
                emu_.Get<GuestCpuReset>().WatchdogReset();
            } else {
                dms_armed_ = true;
            }
            return;
        /* nk.exe StartUp 0x9F0B5DE0/0x9F0B5DF4: 0xB1A strobe (1 then 0). */
        case 0xB1A: return;
        /* sub_9F0B8720 suspend: 0x010-0x01E save/restore; 0x1130 RMW. */
        case 0x010: case 0x012: case 0x014: case 0x016:
        case 0x018: case 0x01A: case 0x01C: case 0x01E:
            suspend_save_[(off - 0x010u) / 2u] = value; return;
        case 0x1130: reg_1130_ = value; return;
        /* sub_9F0B8720 power-down: writes 0x300/0x1114/0xE0C/0x712. */
        case 0x300:
        case 0x1114: case 0xE0C: case 0x712:
            return;
        /* ddi.dll sub_1380C50/sub_1381C54 RMW bit0: 0xA00 &=~1, 0xA02 |=1; nk.exe sub_9F0B8720 writes 0xA00=1. */
        case 0xA00: reg_0A00_ = value; MaybePublishDisplaySize(); return;
        case 0xA02: reg_0A02_ = value; MaybePublishDisplaySize(); return;
        /* socket.dll sub_1301008 RMW / nk.exe sub_9F0B8720 write 0xB00/0xB10 (socket control regs). */
        case 0xB00: reg_0B00_ = value; return;
        case 0xB10: reg_0B10_ = value; return;
        case 0xB02: reg_0B02_ = value; return;   /* nk.exe sub_9F0DF940 socket int-enable RMW */
        case 0xB1E: reg_0B1E_ = value; return;   /* serial.dll sub_1331FE0 RMW bit0 @0x133222C */
        /* nk.exe sub_9F0B7108 backlight: 0x308 brightness (0xF0), 0x30A (0/0x30). */
        case 0x308: case 0x30A: return;
        /* pcmcia.dll sub_1355CF0/sub_1355DC4 RMW 0x920/0x922/0x1112 enables; the 0x900
           command block (sub_1355B78/sub_1355B00) writes 0x900 cmd, 0x904 param, 0x910,
           0x912 trigger (0x8101). */
        case 0x920:  reg_0920_ = value; return;
        case 0x922:  reg_0922_ = value; return;
        case 0x1112: reg_1112_ = value; return;
        case 0x900: case 0x904: case 0x910: case 0x912: return;
        default: break;
    }
    HaltUnsupportedAccess("Casio ASIC WriteReg", kBase + off, value);
}

uint8_t CasioToricomailAsic::ReadByte(uint32_t addr) {
    const uint32_t off = addr - kBase;
    if (InFb(off)) return fb_[off - kFbOffset];
    HaltUnsupportedAccess("Casio ASIC ReadByte", addr, 0);
}

uint16_t CasioToricomailAsic::ReadHalf(uint32_t addr) {
    const uint32_t off = addr - kBase;
    if (InFb(off)) { uint16_t v; std::memcpy(&v, &fb_[off - kFbOffset], sizeof(v)); return v; }
    return ReadReg(off);
}

uint32_t CasioToricomailAsic::ReadWord(uint32_t addr) {
    const uint32_t off = addr - kBase;
    if (InFb(off)) { uint32_t v; std::memcpy(&v, &fb_[off - kFbOffset], sizeof(v)); return v; }
    /* ddi.dll blit sub_13815A8 drives the blit registers as 32-bit words; the 16-bit bus
       splits each into low-then-high halfword accesses. */
    return static_cast<uint32_t>(ReadReg(off)) |
           (static_cast<uint32_t>(ReadReg(off + 2u)) << 16);
}

void CasioToricomailAsic::WriteByte(uint32_t addr, uint8_t value) {
    const uint32_t off = addr - kBase;
    if (InFb(off)) { fb_[off - kFbOffset] = value; return; }
    HaltUnsupportedAccess("Casio ASIC WriteByte", addr, value);
}

void CasioToricomailAsic::WriteHalf(uint32_t addr, uint16_t value) {
    const uint32_t off = addr - kBase;
    if (InFb(off)) { std::memcpy(&fb_[off - kFbOffset], &value, sizeof(value)); return; }
    WriteReg(off, value);
}

void CasioToricomailAsic::WriteWord(uint32_t addr, uint32_t value) {
    const uint32_t off = addr - kBase;
    if (InFb(off)) { std::memcpy(&fb_[off - kFbOffset], &value, sizeof(value)); return; }
    /* ddi.dll blit sub_13815A8 drives the blit registers as 32-bit words; the 16-bit bus
       splits each into low-then-high halfword accesses. */
    WriteReg(off,      static_cast<uint16_t>(value & 0xFFFFu));
    WriteReg(off + 2u, static_cast<uint16_t>(value >> 16));
}

void CasioToricomailAsic::SaveState(StateWriter& w) {
    w.Write<uint64_t>(fb_.size());
    if (!fb_.empty()) w.WriteBytes(fb_.data(), fb_.size());
    w.Write(fill_value_); w.Write(fill_width_); w.Write(fill_height_);
    w.Write(fill_dst_lo_); w.Write(fill_dst_hi_);
    w.Write(fill_src_lo_); w.Write(fill_src_hi_); w.Write(blit_rop_); w.Write(blit_mode_);
    w.Write(blit7_ctl_); w.Write(blit7_width_); w.Write(blit7_height_);
    w.Write(blit7_src_lo_); w.Write(blit7_src_hi_); w.Write(blit7_dst_lo_); w.Write(blit7_dst_hi_);
    w.Write(int_status_); w.Write(int_enable_);
    w.Write(side_buttons_);
    w.Write(reg_1000_);
    w.Write(reg_1002_); w.Write(reg_1010_); w.Write(reg_1134_);
    w.Write(reg_7a0_); w.Write(reg_7a2_); w.Write(reg_7a4_);
    w.Write(reg_40a_); w.Write(reg_406_);
    for (uint16_t v : suspend_save_) w.Write(v);
    w.Write(reg_1130_);
    w.Write(reg_0A00_); w.Write(reg_0A02_);
    size_latch_.SaveState(w);
    w.Write(reg_1120_);
    w.Write(reg_0920_); w.Write(reg_0922_); w.Write(reg_1112_);
    w.Write(reg_0B00_); w.Write(reg_0B10_); w.Write(reg_0B02_);
    w.Write(reg_0B1E_);
    w.Write<uint8_t>(dms_armed_ ? 1u : 0u);
}

void CasioToricomailAsic::RestoreState(StateReader& r) {
    uint64_t n = 0; r.Read(n);
    if (n != kFbSize) {
        emu_.Get<Fatal>().Die("CasioToricomailAsic::RestoreState: framebuffer is %llu bytes, "
                              "expected %u", static_cast<unsigned long long>(n), kFbSize);
    }
    fb_.assign(kFbSize, 0u);
    r.ReadBytes(fb_.data(), fb_.size());
    r.Read(fill_value_); r.Read(fill_width_); r.Read(fill_height_);
    r.Read(fill_dst_lo_); r.Read(fill_dst_hi_);
    r.Read(fill_src_lo_); r.Read(fill_src_hi_); r.Read(blit_rop_); r.Read(blit_mode_);
    r.Read(blit7_ctl_); r.Read(blit7_width_); r.Read(blit7_height_);
    r.Read(blit7_src_lo_); r.Read(blit7_src_hi_); r.Read(blit7_dst_lo_); r.Read(blit7_dst_hi_);
    r.Read(int_status_); r.Read(int_enable_);
    r.Read(side_buttons_);
    side_buttons_ = 0;   /* no physical side button is held after restore (hibernation.md) */
    r.Read(reg_1000_);
    r.Read(reg_1002_); r.Read(reg_1010_); r.Read(reg_1134_);
    r.Read(reg_7a0_); r.Read(reg_7a2_); r.Read(reg_7a4_);
    r.Read(reg_40a_); r.Read(reg_406_);
    for (uint16_t& v : suspend_save_) r.Read(v);
    r.Read(reg_1130_);
    r.Read(reg_0A00_); r.Read(reg_0A02_);
    size_latch_.RestoreState(r);
    r.Read(reg_1120_);
    r.Read(reg_0920_); r.Read(reg_0922_); r.Read(reg_1112_);
    r.Read(reg_0B00_); r.Read(reg_0B10_); r.Read(reg_0B02_);
    r.Read(reg_0B1E_);
    uint8_t armed = 1; r.Read(armed); dms_armed_ = (armed != 0);
}

void CasioToricomailAsic::PostRestore() {
    std::lock_guard<std::mutex> lk(int_mtx_);
    side_btn_int_asserted_ =
        (side_buttons_ & int_status_ & int_enable_ & kSideBtnIntMask) != 0;
    emu_.Get<Vr41xxGiu>().SetPinLevel(kSideBtnGiuPin, !side_btn_int_asserted_);
}

REGISTER_SERVICE(CasioToricomailAsic);
