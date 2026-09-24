#include "vga_controller.h"

#include "../../core/log.h"
#include "../../lcd/lcd_pixel_expand.h"
#include "../../state/state_stream.h"

#include <algorithm>
#include <cstring>

namespace {
constexpr uint32_t kAttrIndexData = 0x3C0;  /* index + data via flip-flop  */
constexpr uint32_t kAttrReadData  = 0x3C1;
constexpr uint32_t kMiscWrite     = 0x3C2;
constexpr uint32_t kSeqIndex      = 0x3C4;
constexpr uint32_t kSeqData       = 0x3C5;
constexpr uint32_t kDacPelMask    = 0x3C6;  /* + hidden command via 4-read  */
constexpr uint32_t kDacReadIndex  = 0x3C7;
constexpr uint32_t kDacWriteIndex = 0x3C8;
constexpr uint32_t kDacData       = 0x3C9;
constexpr uint32_t kFeatureCtrl   = 0x3CA;
constexpr uint32_t kMiscRead      = 0x3CC;
constexpr uint32_t kGcIndex       = 0x3CE;
constexpr uint32_t kGcData        = 0x3CF;
constexpr uint32_t kCrtcIndex     = 0x3D4;
constexpr uint32_t kCrtcData      = 0x3D5;
constexpr uint32_t kExtMode       = 0x3D8;  /* chip extension (stored)      */
constexpr uint32_t kExtColor      = 0x3D9;
constexpr uint32_t kInputStatus1  = 0x3DA;  /* read resets attr flip-flop   */
constexpr uint32_t kPllIndex      = 0x43C8; /* pixel-clock PLL (timing only)*/
constexpr uint32_t kPllData       = 0x43C9;

constexpr uint8_t kCrH_Disp    = 0x01;
constexpr uint8_t kCrOverflow  = 0x07;
constexpr uint8_t kCrStartHi   = 0x0C;
constexpr uint8_t kCrStartLo   = 0x0D;
constexpr uint8_t kCrV_DispEnd = 0x12;
constexpr uint8_t kCrOffset    = 0x13;
}  /* namespace */

VgaController::VgaController() : fb_(kFbSize, 0u) {}

/* Geometry - derived from the CRTC exactly as a real VGA (QEMU vga.c
   vga_get_resolution / vga_get_params). */
uint32_t VgaController::Width() const {
    return ((uint32_t)cr_[kCrH_Disp] + 1u) * 8u;
}
uint32_t VgaController::Height() const {
    const uint32_t ov = cr_[kCrOverflow];
    return (cr_[kCrV_DispEnd] | ((ov & 0x02u) << 7) | ((ov & 0x40u) << 3)) + 1u;
}
uint32_t VgaController::StrideBytes() const {
    return (uint32_t)cr_[kCrOffset] << 3;
}
uint32_t VgaController::StartByte() const {
    return ((uint32_t)cr_[kCrStartLo] | ((uint32_t)cr_[kCrStartHi] << 8)) * 4u;
}
/* RAMDAC hidden command register selects depth: the driver writes 0x32 for
   16bpp 5-6-5 hicolor and 0x00 for 8bpp palettized (sub_10004CA4). */
uint32_t VgaController::Bpp() const {
    return (dac_command_ & 0x30u) ? 16u : 8u;
}

bool VgaController::CurrentMode(uint32_t& w, uint32_t& h, uint32_t& bpp) const {
    w = Width(); h = Height(); bpp = Bpp();
    return w > 0 && h > 0 && StrideBytes() > 0;
}

bool VgaController::HasFrame() {
    /* Valid geometry and the Sequencer screen-disable bit clear (SR[01].5). */
    return Width() > 0 && Height() > 0 && StrideBytes() > 0 &&
           !(sr_[0x01] & 0x20u);
}

uint8_t VgaController::ReadReg8(uint32_t port) {
    if (port != kDacPelMask) pelmask_reads_ = 0;   /* breaks the unlock run */

    switch (port) {
        case kAttrIndexData: return attr_index_;
        case kAttrReadData:  return ar_[attr_index_ & 0x1Fu];
        case kMiscWrite:
        case kMiscRead:      return misc_;
        case kSeqIndex:      return seq_index_;
        case kSeqData:       return sr_[seq_index_];
        case kDacPelMask:
            if (pelmask_reads_ >= 4u) { pelmask_reads_ = 0; return dac_command_; }
            ++pelmask_reads_;
            return 0xFFu;                            /* PEL mask all-ones    */
        case kDacReadIndex:  return dac_read_idx_;
        case kDacWriteIndex: return dac_write_idx_;
        case kDacData: {
            const uint8_t v = (uint8_t)(dac_pal_[dac_read_idx_][dac_comp_] & 0x3Fu);
            if (++dac_comp_ == 3) { dac_comp_ = 0; ++dac_read_idx_; }
            return v;
        }
        case kGcIndex:   return gc_index_;
        case kGcData:    return gr_[gc_index_];
        case kCrtcIndex: return crtc_index_;
        case kCrtcData:  return cr_[crtc_index_];
        case kInputStatus1:
            attr_flipflop_ = false;
            return 0u;                               /* no live retrace bits */
        case kFeatureCtrl: case kExtMode: case kExtColor:
        case kPllIndex:    case kPllData:
            return 0u;                               /* timing-only, not read */
        default:
#if CERF_DEV_MODE
            LOG(Periph, "[VgaController] read unhandled reg 0x%X\n", port);
#endif
            return 0u;
    }
}

void VgaController::WriteReg8(uint32_t port, uint8_t value) {
    if (port != kDacPelMask) pelmask_reads_ = 0;

    switch (port) {
        case kAttrIndexData:
            if (!attr_flipflop_) attr_index_ = value & 0x3Fu;  /* +PAS bit 5 */
            else                 ar_[attr_index_ & 0x1Fu] = value;
            attr_flipflop_ = !attr_flipflop_;
            return;
        case kMiscWrite: misc_ = value; return;
        case kSeqIndex:  seq_index_ = value; return;
        case kSeqData:   sr_[seq_index_] = value; return;
        case kDacPelMask:
            /* After the 4-read unlock the write lands on the command register;
               otherwise it is an (ignored) PEL-mask write. */
            if (pelmask_reads_ >= 4u) dac_command_ = value;
            pelmask_reads_ = 0;
            return;
        case kDacReadIndex:  dac_read_idx_  = value; dac_comp_ = 0; return;
        case kDacWriteIndex: dac_write_idx_ = value; dac_comp_ = 0; return;
        case kDacData:
            if (dac_comp_ < 2) {
                dac_rgb_latch_[dac_comp_] = value & 0x3Fu;
            } else {
                dac_pal_[dac_write_idx_][0] = dac_rgb_latch_[0];
                dac_pal_[dac_write_idx_][1] = dac_rgb_latch_[1];
                dac_pal_[dac_write_idx_][2] = value & 0x3Fu;
            }
            if (++dac_comp_ == 3) { dac_comp_ = 0; ++dac_write_idx_; }
            return;
        case kGcIndex:   gc_index_ = value; return;
        case kGcData:    gr_[gc_index_] = value; return;
        case kCrtcIndex: crtc_index_ = value; return;
        case kCrtcData:  cr_[crtc_index_] = value; return;
        case kInputStatus1: attr_flipflop_ = false; return; /* RO on real HW */
        case kFeatureCtrl: case kExtMode: case kExtColor:
        case kPllIndex:    case kPllData:
            return;                                  /* timing-only, no effect */
        default:
#if CERF_DEV_MODE
            LOG(Periph, "[VgaController] write unhandled reg 0x%X = 0x%02X\n",
                port, value);
#endif
            return;
    }
}

void VgaController::SaveState(StateWriter& w) const {
    w.WriteBytes("cr", cr_, sizeof(cr_));
    w.WriteBytes("sr", sr_, sizeof(sr_));
    w.WriteBytes("gr", gr_, sizeof(gr_));
    w.WriteBytes("ar", ar_, sizeof(ar_));
    w.Write("misc", misc_);
    w.Write("crtc_index", crtc_index_); w.Write("seq_index", seq_index_); w.Write("gc_index", gc_index_); w.Write("attr_index", attr_index_);
    w.Write<uint8_t>("attr_flipflop", attr_flipflop_ ? 1u : 0u);
    w.WriteBytes("dac_pal", dac_pal_, sizeof(dac_pal_));
    w.WriteBytes("fb", fb_.data(), fb_.size());
}

void VgaController::RestoreState(StateReader& r) {
    r.ReadBytes("cr", cr_, sizeof(cr_));
    r.ReadBytes("sr", sr_, sizeof(sr_));
    r.ReadBytes("gr", gr_, sizeof(gr_));
    r.ReadBytes("ar", ar_, sizeof(ar_));
    r.Read("misc", misc_);
    r.Read("crtc_index", crtc_index_); r.Read("seq_index", seq_index_); r.Read("gc_index", gc_index_); r.Read("attr_index", attr_index_);
    uint8_t ff = 0; r.Read("attr_flipflop", ff); attr_flipflop_ = (ff != 0);
    r.ReadBytes("dac_pal", dac_pal_, sizeof(dac_pal_));
    r.ReadBytes("fb", fb_.data(), fb_.size());
}

void VgaController::RenderInto(uint32_t* dib, uint32_t dst_w, uint32_t dst_h) {
    std::memset(dib, 0, (size_t)dst_w * dst_h * 4u);

    const uint32_t gw = Width(), gh = Height();
    const uint32_t stride = StrideBytes();
    const uint32_t start  = StartByte();
    const uint32_t bpp    = Bpp();
    if (gw == 0 || gh == 0 || stride == 0) return;

    const uint8_t* fb = fb_.data();
    const uint32_t cw = std::min(dst_w, gw);
    const uint32_t ch = std::min(dst_h, gh);

    for (uint32_t y = 0; y < ch; ++y) {
        uint32_t* row = dib + (size_t)y * dst_w;
        const uint32_t line = start + y * stride;
        if (bpp == 8u) {
            for (uint32_t x = 0; x < cw; ++x) {
                const uint32_t at = (line + x) % kFbSize;
                const uint8_t* c = dac_pal_[fb[at]];
                row[x] = lcd_pixel::PackXrgb(lcd_pixel::Expand6(c[0]), lcd_pixel::Expand6(c[1]),
                                             lcd_pixel::Expand6(c[2]));
            }
        } else {  /* 16bpp 5-6-5 */
            for (uint32_t x = 0; x < cw; ++x) {
                const uint32_t at = (line + x * 2u) % kFbSize;
                row[x] = lcd_pixel::Expand565(
                    (uint16_t)(fb[at] | (fb[(at + 1u) % kFbSize] << 8)));
            }
        }
    }
}
