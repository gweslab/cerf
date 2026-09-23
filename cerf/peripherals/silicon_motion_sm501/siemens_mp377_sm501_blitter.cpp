#define NOMINMAX

#include "siemens_mp377_sm501_blitter.h"
#include "siemens_mp377_sm501_fb.h"
#include "siemens_mp377_sm501_internal.h"
#include "../../lcd/lcd_pixel_expand.h"
#include "siemens_mp377_sm501_rop.h"
#include "sm501_line_rasterizer.h"

#include "../../boards/board_context.h"
#include "../../boards/siemens_mp377/siemens_mp377_id.h"

#include "../../core/cerf_emulator.h"
#include "../../socs/guest_cpu_reset.h"

#include <algorithm>
#include <cstdint>
#include <vector>
namespace siemens_mp377 {

bool SiemensMp377Sm501Blitter::ShouldRegister() {
    auto* board = emu_.TryGet<BoardContext>();
    return board && board->GetBoardId() == BoardId::SiemensMp377;
}

void SiemensMp377Sm501Blitter::OnReady() {
    Reset();
    emu_.Get<GuestCpuReset>().RegisterResetListener([this](ResetLineKind) {
        if (!emu_.Get<GuestCpuReset>().DeliveredResetWasResume()) Reset();
    });
}

void SiemensMp377Sm501Blitter::ExecuteCommand(uint32_t command) {
    ExecuteDdiVgx2dCommand(command);
}

void SiemensMp377Sm501Blitter::WriteDataPort(uint32_t value) {
    HandleDdiVgxDataPortWord(value);
}

uint32_t SiemensMp377Sm501Blitter::R(uint32_t off) const {
    return emu_.Get<SiemensMp377Sm501Regs>().ReadSm501Register(off);
}
uint32_t SiemensMp377Sm501Blitter::DecodePitchField(uint32_t p, uint32_t fallback) const {
    return p != 0u ? p : fallback;
}
uint32_t SiemensMp377Sm501Blitter::DecodeDstPitchPixels() const {
    return DecodePitchField(DstPitchField(R(k2dPitch)), (R(k2dWindowWidth) >> 16) & 0x1FFFu);
}
uint32_t SiemensMp377Sm501Blitter::DecodeSrcPitchPixels() const {
    return DecodePitchField(SrcPitchField(R(k2dPitch)), DecodeDstPitchPixels());
}
SiemensMp377Sm501Blitter::SurfaceState SiemensMp377Sm501Blitter::DecodeSurface(bool source, uint32_t cmd) const {
    SiemensMp377Sm501Blitter::SurfaceState s;
    const uint32_t raw_base = R(source ? k2dSourceBase : k2dDestinationBase);
    s.base = NormalizeFbOffset(raw_base);
    const uint32_t window = R(k2dWindowWidth);
    s.width_pixels = source ? (window & 0x1FFFu) : ((window >> 16) & 0x1FFFu);
    s.pitch_pixels = source ? DecodeSrcPitchPixels() : DecodeDstPitchPixels();
    const bool mono = source && HostWriteIsMonochrome(cmd);
    const uint32_t bpp = mono ? 1u : 16u;
    s.pitch_bytes = std::max<uint32_t>(1u, (s.pitch_pixels * bpp + 7u) / 8u);
    if (!mono && s.pitch_bytes < s.pitch_pixels * 2u) s.pitch_bytes = s.pitch_pixels * 2u;
    return s;
}
SiemensMp377Sm501Blitter::State2d SiemensMp377Sm501Blitter::DecodeState2d(uint32_t cmd) const {
    const uint32_t src_xy = R(k2dSource);
    const uint32_t dst_xy = R(k2dDestination);
    const uint32_t extent = R(k2dDimension);
    SiemensMp377Sm501Blitter::State2d st;
    st.src_x = SourceX(src_xy);
    st.src_y = SourceY(src_xy);
    st.dst_x = DestinationX(dst_xy);
    st.dst_y = DestinationY(dst_xy);
    st.width = DimensionX(extent);
    st.height = DimensionY(extent);
    st.src_surface = DecodeSurface(true, cmd);
    st.dst_surface = DecodeSurface(false, cmd);
    st.src_pitch = st.src_surface.pitch_pixels;
    st.dst_pitch = st.dst_surface.pitch_pixels;
    st.fill_color = DecodeDdiColorRegister(k2dForeground);
    st.inv_fg = DecodeDdiColorRegister(k2dBackground);
    st.control = cmd;
    st.backwards = (cmd & 0x08000000u) != 0;
    const uint32_t clip_tl = R(k2dClipTopLeft);
    const uint32_t clip_br = R(k2dClipBottomRight);
    st.clip_enabled = (clip_tl & (1u << 13)) != 0u;
    st.clip_excludes_inside = (clip_tl & (1u << 12)) != 0u;
    st.clip_left = clip_tl & 0x0FFFu;
    st.clip_top = clip_tl >> 16;
    st.clip_right = clip_br & 0x1FFFu;
    st.clip_bottom = clip_br >> 16;
    return st;
}
bool SiemensMp377Sm501Blitter::DestinationPixelEnabled(const State2d& st, uint32_t x, uint32_t y) const {
    if (!st.clip_enabled) return true;
    /* siemens_mp377_v1040 ddi_vgx.dll sub_2996AB8; Win32 RECT. */
    const bool inside = x >= st.clip_left && x < st.clip_right && y >= st.clip_top && y < st.clip_bottom;
    return st.clip_excludes_inside ? !inside : inside;
}
uint32_t SiemensMp377Sm501Blitter::NormalizeFbOffset(uint32_t v) const {
    uint32_t off = 0;
    if (Sm501FbPaToOffset(v, off)) return off;
    if (v < kSm501FbBytes) return v;
    return 0u;
}
void SiemensMp377Sm501Blitter::FillRect16(const SiemensMp377Sm501Blitter::State2d& st, uint16_t color) {
    auto& fb = emu_.Get<SiemensMp377Sm501Fb>();
    uint8_t* vram = fb.MutableVramFor2d();
    if (!vram) return;
    const SiemensMp377Sm501Blitter::SurfaceState& dst = st.dst_surface;
    const uint32_t surface_w = SurfaceWidthPixels16(dst);
    const uint32_t surface_h = SurfaceHeightRows(dst);
    if (surface_w == 0 || surface_h == 0) return;
    if (st.dst_x >= surface_w || st.dst_y >= surface_h) return;
    const uint32_t width = std::min(st.width, surface_w - st.dst_x);
    const uint32_t height = std::min(st.height, surface_h - st.dst_y);
    if (width == 0 || height == 0) return;
    const uint32_t stride = dst.pitch_bytes ? dst.pitch_bytes : st.dst_pitch * 2u;
    if (stride == 0) return;
    for (uint32_t y = 0; y < height; ++y) {
        const uint32_t row = dst.base + (st.dst_y + y) * stride + st.dst_x * 2u;
        if (row >= kSm501FbBytes) break;
        const uint32_t row_bytes = std::min(width * 2u, kSm501FbBytes - row);
        for (uint32_t x = 0; x + 1u < row_bytes; x += 2u) {
            if (!DestinationPixelEnabled(st, st.dst_x + (x >> 1), st.dst_y + y)) continue;
            Sm501RasterOpPixel16(vram + row + x, st.control, color, color);
        }
        fb.Note2dWrite(row, row_bytes);
    }
}
uint16_t SiemensMp377Sm501Blitter::DecodeDdiColorRegister(uint32_t off) const {
    return static_cast<uint16_t>(R(off) & 0xFFFFu);
}
void SiemensMp377Sm501Blitter::BeginDdiVgxHostDataCommand(uint32_t cmd) {
    host_data_active_ = true;
    host_data_mono_ = HostWriteIsMonochrome(cmd);
    const uint32_t dst_xy = R(k2dDestination);
    const uint32_t wh = R(k2dDimension);
    host_dst_x_ = DestinationX(dst_xy);
    host_dst_y_ = DestinationY(dst_xy);
    host_width_ = DimensionX(wh);
    host_height_ = DimensionY(wh);
    const SiemensMp377Sm501Blitter::State2d st = DecodeState2d(cmd);
    host_data_active_ = host_width_ != 0u && host_height_ != 0u;
    host_dst_pitch_bytes_ = st.dst_surface.pitch_bytes;
    host_dst_surface_width_ = SurfaceWidthPixels16(st.dst_surface);
    host_dst_surface_height_ = SurfaceHeightRows(st.dst_surface);
    host_dst_base_ = st.dst_surface.base;
    host_fg_ = st.fill_color;
    host_bg_ = st.inv_fg;
    host_mono_transparent_ = host_data_mono_ && TransparencyEnabled(cmd);
    host_clip_enabled_ = st.clip_enabled;
    host_clip_excludes_inside_ = st.clip_excludes_inside;
    host_clip_left_ = st.clip_left;
    host_clip_top_ = st.clip_top;
    host_clip_right_ = st.clip_right;
    host_clip_bottom_ = st.clip_bottom;
    host_y_ = 0;
    host_src_byte_in_row_ = 0;
    host_src_bit_offset_ = 0;
    host_row_bytes_.clear();
    if (host_data_mono_) {
        const uint32_t src_field = R(k2dSource);
        /* SM501 Databook v1.02 section 4, 2D Source: host-write
           monochrome alignment is bits[20:16]. */
        host_src_bit_offset_ = (src_field >> 16) & 0x1Fu;
        const uint32_t active_bits = host_src_bit_offset_ + host_width_;
        host_src_active_bytes_ = (active_bits + 7u) / 8u;
        /* SM501 Databook v1.02 sections 1 and 4; siemens_mp377_v1040
           ddi_vgx.dll sub_2992E70. */
        host_src_pitch_bytes_ = (host_src_active_bytes_ + 3u) & ~3u;
    } else {
        host_src_bit_offset_ = 0;
        host_src_active_bytes_ = (host_width_ * kDdiHostColorBpp + 7u) / 8u;
        host_src_pitch_bytes_ = (host_src_active_bytes_ + 7u) & ~7u;
        host_row_bytes_.clear();
        host_row_bytes_.reserve(host_src_pitch_bytes_);
    }
}
void SiemensMp377Sm501Blitter::CompleteHostDataIfDone() {
    if (!host_data_active_) return;
    if (host_y_ >= host_height_) {
        host_data_active_ = false;
        host_row_bytes_.clear();
    }
}
void SiemensMp377Sm501Blitter::HostDataWritePixel(uint32_t x, uint32_t y, uint16_t p) {
    auto& fb = emu_.Get<SiemensMp377Sm501Fb>();
    const uint32_t abs_x = host_dst_x_ + x;
    const uint32_t abs_y = host_dst_y_ + y;
    if (host_clip_enabled_) {
        /* siemens_mp377_v1040 ddi_vgx.dll sub_2996AB8; Win32 RECT. */
        const bool inside = abs_x >= host_clip_left_ && abs_x < host_clip_right_ &&
                            abs_y >= host_clip_top_ && abs_y < host_clip_bottom_;
        if (host_clip_excludes_inside_ ? inside : !inside) return;
    }
    if (host_dst_surface_width_ && abs_x >= host_dst_surface_width_) return;
    if (host_dst_surface_height_ && abs_y >= host_dst_surface_height_) return;
    uint8_t* vram = fb.MutableVramFor2d();
    if (!vram) return;
    const uint32_t stride = host_dst_pitch_bytes_;
    const uint32_t off = host_dst_base_ + abs_y * stride + abs_x * 2u;
    if (off + 1u >= kSm501FbBytes) return;
    cerf::le::Put16(vram + off, p);
    fb.Note2dWrite(off, 2u);
}
void SiemensMp377Sm501Blitter::HostDataAdvanceRow() {
    host_src_byte_in_row_ = 0;
    ++host_y_;
    host_row_bytes_.clear();
    CompleteHostDataIfDone();
}
void SiemensMp377Sm501Blitter::HostDataMonoByte(uint8_t b) {
    if (!host_data_active_) return;
    if (host_src_byte_in_row_ < host_src_active_bytes_ && host_y_ < host_height_) {
        for (int bit = 7; bit >= 0; --bit) {
            const uint32_t bit_in_row = host_src_byte_in_row_ * 8u + static_cast<uint32_t>(7 - bit);
            if (bit_in_row < host_src_bit_offset_) continue;
            const uint32_t px = bit_in_row - host_src_bit_offset_;
            if (px >= host_width_) continue;
            if (b & (1u << bit)) {
                HostDataWritePixel(px, host_y_, host_fg_);
            } else if (!host_mono_transparent_) {
                HostDataWritePixel(px, host_y_, host_bg_);
            }
        }
    }
    ++host_src_byte_in_row_;
    if (host_src_byte_in_row_ >= host_src_pitch_bytes_) {
        HostDataAdvanceRow();
    }
}
uint8_t SiemensMp377Sm501Blitter::HostRowByte(uint32_t i) const {
    return i < host_row_bytes_.size() ? host_row_bytes_[i] : 0;
}
void SiemensMp377Sm501Blitter::FlushHostDataColorRow() {
    if (host_y_ >= host_height_) return;
    for (uint32_t x = 0; x < host_width_; ++x) {
        const uint32_t i = x * 2u;
        const uint16_t p = static_cast<uint16_t>(HostRowByte(i) | (HostRowByte(i + 1u) << 8));
        HostDataWritePixel(x, host_y_, p);
    }
}
void SiemensMp377Sm501Blitter::HostDataColorByte(uint8_t b) {
    if (!host_data_active_) return;
    if (host_src_byte_in_row_ < host_src_active_bytes_ && host_y_ < host_height_) host_row_bytes_.push_back(b);
    ++host_src_byte_in_row_;
    if (host_src_byte_in_row_ >= host_src_pitch_bytes_) {
        FlushHostDataColorRow();
        HostDataAdvanceRow();
    }
}
void SiemensMp377Sm501Blitter::BeginDdiPatternUpload() {
    pattern_upload_active_ = true;
    pattern_valid_ = false;
    pattern_words_.clear();
}
void SiemensMp377Sm501Blitter::FinishDdiPatternUpload() {
    if (!pattern_upload_active_) return;
    pattern_upload_active_ = false;
    pattern_valid_ = !pattern_words_.empty();
}
void SiemensMp377Sm501Blitter::HandleDdiPatternDataPortWord(uint32_t v) {
    if (!pattern_upload_active_) emu_.Get<Fatal>().Die("MP377 SM501 2D pattern data without an active upload");
    /* SM501 MMCC Databook v1.02, sections 1 and 4. */
    if (pattern_words_.size() >= 64u)
        emu_.Get<Fatal>().Die("MP377 SM501 2D pattern upload exceeds 8x8x32-bpp payload");
    pattern_words_.push_back(v);
}
uint16_t SiemensMp377Sm501Blitter::PatternPixel565(const State2d& st, uint32_t x, uint32_t y) {
    /* SM501 Databook v1.02 section 4: 2D Control bit 30 selects
       monochrome or colour pattern; 2D Stretch & Format supplies the
       8x8 pattern origin; DPR34/DPR38 contain the 64 monochrome bits. */
    const uint32_t stretch = R(k2dStretchAndFormat);
    const bool use_origin = (stretch & (1u << 30)) != 0u || ((stretch >> 16) & 0xFu) == 0xFu;
    const uint32_t origin_x = use_origin ? ((stretch >> 23) & 7u) : 0u;
    const uint32_t origin_y = use_origin ? ((stretch >> 27) & 7u) : 0u;
    const uint32_t px = (st.dst_x + x - origin_x) & 7u;
    const uint32_t py = (st.dst_y + y - origin_y) & 7u;
    const uint32_t i = py * 8u + px;
    if (!ColorPatternSelected(st.control)) {
        const uint64_t pattern = static_cast<uint64_t>(R(k2dMonoPatternLow)) |
                                 (static_cast<uint64_t>(R(k2dMonoPatternHigh)) << 32);
        return ((pattern >> i) & 1u) != 0u ? st.fill_color : st.inv_fg;
    }
    /* SM501 Databook v1.02 section 4, 2D Stretch & Format: Format selects
       8-, 16-, or 32-bpp pixels.  A colour pattern is the 8x8 payload
       previously written through the 2D Engine Data Port. */
    const uint32_t format = (stretch >> 20) & 3u;
    if (!pattern_valid_)
        emu_.Get<Fatal>().Die("MP377 SM501 2D colour pattern used before data-port load");
    if (format == 1u && pattern_words_.size() >= 32u) {
        const uint32_t w = pattern_words_[i / 2u];
        return static_cast<uint16_t>((i & 1u) ? (w >> 16) : (w & 0xFFFFu));
    }
    if (format == 2u && pattern_words_.size() >= 64u) {
        return lcd_pixel::PackRgb565(pattern_words_[i]);
    }
    emu_.Get<Fatal>().Die("MP377 SM501 unsupported or incomplete 2D colour pattern format=%u words=%zu", format,
                          pattern_words_.size());
}
void SiemensMp377Sm501Blitter::HandleDdiVgxDataPortWord(uint32_t v) {
    /* SM501 Databook v1.02 sections 1 and 4; siemens_mp377_v1040
       ddi_vgx.dll sub_2992E70. */
    const uint32_t control = R(k2dControl);
    if (!host_data_active_ && !pattern_upload_active_ && ColorPatternSelected(control) &&
        !DrawingEngineStarted(control)) {
        BeginDdiPatternUpload();
    }
    if (pattern_upload_active_) {
        HandleDdiPatternDataPortWord(v);
        return;
    }
    if (!host_data_active_) emu_.Get<Fatal>().Die("MP377 SM501 2D host data without an active command");
    uint8_t bytes[4];
    cerf::le::Put32(bytes, v);
    for (const uint8_t b : bytes) {
        if (host_data_mono_) HostDataMonoByte(b);
        else                 HostDataColorByte(b);
    }
}
void SiemensMp377Sm501Blitter::ExecuteDdiFill(const SiemensMp377Sm501Blitter::State2d& st) {
    FillRect16(st, st.fill_color);
}

void SiemensMp377Sm501Blitter::ExecuteDdiLineDraw(const SiemensMp377Sm501Blitter::State2d& st) {
    auto& fb = emu_.Get<SiemensMp377Sm501Fb>();
    uint8_t* vram = fb.MutableVramFor2d();
    if (!vram) return;
    const Sm501LineState line{vram, kSm501FbBytes, st.dst_surface.base, st.dst_surface.pitch_bytes,
                              SurfaceWidthPixels16(st.dst_surface), SurfaceHeightRows(st.dst_surface),
                              st.dst_x, st.dst_y, R(k2dSource), R(k2dDimension), st.control, st.fill_color,
                              st.clip_enabled, st.clip_excludes_inside, st.clip_left, st.clip_top,
                              st.clip_right, st.clip_bottom};
    const Sm501LineDirtyRange dirty = RasterizeSm501Line(line);
    if (dirty.size != 0u) fb.Note2dWrite(dirty.offset, dirty.size);
}
uint32_t SiemensMp377Sm501Blitter::SurfaceWidthPixels16(const SiemensMp377Sm501Blitter::SurfaceState& s) const {
    if (s.width_pixels) return s.width_pixels;
    if (s.pitch_pixels) return s.pitch_pixels;
    return s.pitch_bytes >= 2u ? s.pitch_bytes / 2u : 0u;
}
uint32_t SiemensMp377Sm501Blitter::SurfaceHeightRows(const SiemensMp377Sm501Blitter::SurfaceState& s) const {
    if (s.base >= kSm501FbBytes || s.pitch_bytes == 0) return 0;
    return (kSm501FbBytes - s.base) / s.pitch_bytes;
}
SiemensMp377Sm501Blitter::VramBlitRect
SiemensMp377Sm501Blitter::NormalizeVramBlitRect(const SiemensMp377Sm501Blitter::State2d& st) const {
    SiemensMp377Sm501Blitter::VramBlitRect r;
    r.src_x = st.src_x;
    r.src_y = st.src_y;
    r.dst_x = st.dst_x;
    r.dst_y = st.dst_y;
    r.width = st.width;
    r.height = st.height;
    r.rtl_btl = st.backwards;
    if (r.rtl_btl) {
        if (r.width) {
            r.src_x = (r.src_x + 1u >= r.width) ? (r.src_x - r.width + 1u) : 0u;
            r.dst_x = (r.dst_x + 1u >= r.width) ? (r.dst_x - r.width + 1u) : 0u;
        }
        if (r.height) {
            r.src_y = (r.src_y + 1u >= r.height) ? (r.src_y - r.height + 1u) : 0u;
            r.dst_y = (r.dst_y + 1u >= r.height) ? (r.dst_y - r.height + 1u) : 0u;
        }
    }
    const uint32_t src_w = SurfaceWidthPixels16(st.src_surface);
    const uint32_t dst_w = SurfaceWidthPixels16(st.dst_surface);
    const uint32_t src_h = SurfaceHeightRows(st.src_surface);
    const uint32_t dst_h = SurfaceHeightRows(st.dst_surface);
    if (r.src_x >= src_w || r.src_y >= src_h || r.dst_x >= dst_w || r.dst_y >= dst_h) {
        r.width = 0;
        r.height = 0;
        return r;
    }
    r.width = std::min(r.width, std::min(src_w - r.src_x, dst_w - r.dst_x));
    r.height = std::min(r.height, std::min(src_h - r.src_y, dst_h - r.dst_y));
    return r;
}
void SiemensMp377Sm501Blitter::ExecuteDdiVideoToVideo(const SiemensMp377Sm501Blitter::State2d& st) {
    const SiemensMp377Sm501Blitter::VramBlitRect r = NormalizeVramBlitRect(st);
    if (r.width == 0 || r.height == 0) return;
    auto& fb = emu_.Get<SiemensMp377Sm501Fb>();
    uint8_t* vram = fb.MutableVramFor2d();
    if (!vram) return;
    const uint32_t src_stride = st.src_surface.pitch_bytes ? st.src_surface.pitch_bytes : st.src_pitch * 2u;
    const uint32_t dst_stride = st.dst_surface.pitch_bytes ? st.dst_surface.pitch_bytes : st.dst_pitch * 2u;
    /* SM501 Databook v1.02, 2D Control bit 27; siemens_mp377_v1040
       ddi_vgx.dll sub_2992948. */
    for (uint32_t yi = 0; yi < r.height; ++yi) {
        const uint32_t y = r.rtl_btl ? r.height - 1u - yi : yi;
        const uint32_t src_row = st.src_surface.base + (r.src_y + y) * src_stride + r.src_x * 2u;
        const uint32_t dst_row = st.dst_surface.base + (r.dst_y + y) * dst_stride + r.dst_x * 2u;
        if (dst_row >= kSm501FbBytes) break;
        for (uint32_t xi = 0; xi < r.width; ++xi) {
            const uint32_t x = r.rtl_btl ? r.width - 1u - xi : xi;
            const uint32_t src_off = src_row + x * 2u;
            const uint32_t dst_off = dst_row + x * 2u;
            if (src_off + 1u >= kSm501FbBytes || dst_off + 1u >= kSm501FbBytes) break;
            if (!DestinationPixelEnabled(st, r.dst_x + x, r.dst_y + y)) continue;
            Sm501RasterOpPixel16(vram + dst_off, st.control, cerf::le::U16(vram, src_off),
                                 st.fill_color);
        }
        fb.Note2dWrite(dst_row, r.width * 2u);
    }
}
void SiemensMp377Sm501Blitter::ExecuteDdiVgx2dCommand(uint32_t cmd) {
    FinishDdiPatternUpload();
    const uint32_t command = CommandField(cmd);
    const uint32_t format = (R(k2dStretchAndFormat) >> 20) & 3u;
    if (format != 1u)
        emu_.Get<Fatal>().Die("MP377 SM501 unsupported 2D pixel format %u", format);
    if (command == 8u) {
        BeginDdiVgxHostDataCommand(cmd);
        return;
    }
    /* SM501 Databook v1.02 section 4, 2D Control command table:
       command 15 is Texture Load and precedes the data-port payload. */
    if (command == 15u) {
        BeginDdiPatternUpload();
        return;
    }
    const SiemensMp377Sm501Blitter::State2d st = DecodeState2d(cmd);
    switch (command) {
    case 0u: {
        if (st.width == 0u || st.height == 0u) return;
        /* SM501 Databook v1.02 section 4, 2D Control bits 15:14 and 7:0. */
        if (Sm501RasterOpDependsOnSource(cmd)) {
            ExecuteDdiVideoToVideo(st);
        } else {
            PatternFillRect16(st);
        }
        return;
    }
    case 1u:
        if (st.width == 0u || st.height == 0u) return;
        ExecuteDdiFill(st);
        return;
    case 7u:
        ExecuteDdiLineDraw(st);
        return;
    default:
        emu_.Get<Fatal>().Die("MP377 SM501 2D unsupported documented command %u control=0x%08X", command, cmd);
    }
}
REGISTER_SERVICE(SiemensMp377Sm501Blitter);

} // namespace siemens_mp377
