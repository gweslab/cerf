#pragma once

#include "siemens_mp377_sm501.h"
#include "sm501_state_vector.h"

#include "../../core/cerf_emulator.h"
#include "../../core/fatal.h"
#include "../../core/service.h"
#include "../../state/state_stream.h"

#include <cstddef>
#include <cstdint>
#include <vector>

namespace siemens_mp377 {

class SiemensMp377Sm501Regs;

/* SM501 datasheet Table 4-1: 2D engine at BAR1+0x100000 and its data-port
   aperture at BAR1+0x110000. */
class SiemensMp377Sm501Blitter : public Service {
public:
    using Service::Service;

    bool ShouldRegister() override;
    void OnReady() override;

    void ExecuteCommand(uint32_t command);
    void WriteDataPort(uint32_t value);
    static bool IsCommandRegister(uint32_t offset) { return offset == 0x10000Cu; }
    static bool IsDataPort(uint32_t offset) { return offset >= 0x110000u && offset < 0x110100u; }

    void SaveState(StateWriter& w) const {
        w.Write("pattern_upload_active", pattern_upload_active_);
        w.Write("pattern_valid", pattern_valid_);
        WriteSm501VectorState(w, "pattern_word_count", "pattern_words", pattern_words_);
        w.Write("host_data_active", host_data_active_);
        w.Write("host_data_mono", host_data_mono_);
        w.Write("host_dst_x", host_dst_x_);
        w.Write("host_dst_y", host_dst_y_);
        w.Write("host_width", host_width_);
        w.Write("host_height", host_height_);
        w.Write("host_dst_pitch_bytes", host_dst_pitch_bytes_);
        w.Write("host_dst_surface_width", host_dst_surface_width_);
        w.Write("host_dst_surface_height", host_dst_surface_height_);
        w.Write("host_dst_base", host_dst_base_);
        w.Write("host_y", host_y_);
        w.Write("host_src_byte_in_row", host_src_byte_in_row_);
        w.Write("host_src_bit_offset", host_src_bit_offset_);
        w.Write("host_src_active_bytes", host_src_active_bytes_);
        w.Write("host_src_pitch_bytes", host_src_pitch_bytes_);
        WriteSm501VectorState(w, "host_row_byte_count", "host_row_bytes", host_row_bytes_);
        w.Write("host_fg", host_fg_);
        w.Write("host_bg", host_bg_);
        w.Write("host_mono_transparent", host_mono_transparent_);
        w.Write("host_clip_enabled", host_clip_enabled_);
        w.Write("host_clip_excludes_inside", host_clip_excludes_inside_);
        w.Write("host_clip_left", host_clip_left_);
        w.Write("host_clip_top", host_clip_top_);
        w.Write("host_clip_right", host_clip_right_);
        w.Write("host_clip_bottom", host_clip_bottom_);
    }

    void RestoreState(StateReader& r) {
        r.Read("pattern_upload_active", pattern_upload_active_);
        r.Read("pattern_valid", pattern_valid_);
        ReadSm501VectorState(r, "pattern_word_count", "pattern_words", pattern_words_, 64u);
        r.Read("host_data_active", host_data_active_);
        r.Read("host_data_mono", host_data_mono_);
        r.Read("host_dst_x", host_dst_x_);
        r.Read("host_dst_y", host_dst_y_);
        r.Read("host_width", host_width_);
        r.Read("host_height", host_height_);
        r.Read("host_dst_pitch_bytes", host_dst_pitch_bytes_);
        r.Read("host_dst_surface_width", host_dst_surface_width_);
        r.Read("host_dst_surface_height", host_dst_surface_height_);
        r.Read("host_dst_base", host_dst_base_);
        r.Read("host_y", host_y_);
        r.Read("host_src_byte_in_row", host_src_byte_in_row_);
        r.Read("host_src_bit_offset", host_src_bit_offset_);
        r.Read("host_src_active_bytes", host_src_active_bytes_);
        r.Read("host_src_pitch_bytes", host_src_pitch_bytes_);
        ReadSm501VectorState(r, "host_row_byte_count", "host_row_bytes", host_row_bytes_, 4096u);
        r.Read("host_fg", host_fg_);
        r.Read("host_bg", host_bg_);
        r.Read("host_mono_transparent", host_mono_transparent_);
        r.Read("host_clip_enabled", host_clip_enabled_);
        r.Read("host_clip_excludes_inside", host_clip_excludes_inside_);
        r.Read("host_clip_left", host_clip_left_);
        r.Read("host_clip_top", host_clip_top_);
        r.Read("host_clip_right", host_clip_right_);
        r.Read("host_clip_bottom", host_clip_bottom_);
    }

private:
    void Reset() {
        pattern_upload_active_ = false;
        pattern_valid_ = false;
        pattern_words_.clear();
        host_data_active_ = false;
        host_data_mono_ = false;
        host_dst_x_ = host_dst_y_ = host_width_ = host_height_ = 0u;
        host_dst_pitch_bytes_ = kFbStride;
        host_dst_surface_width_ = kFbWidth;
        host_dst_surface_height_ = kFbHeight;
        host_dst_base_ = host_y_ = host_src_byte_in_row_ = host_src_bit_offset_ = 0u;
        host_src_active_bytes_ = host_src_pitch_bytes_ = 0u;
        host_row_bytes_.clear();
        host_fg_ = 0xFFFFu;
        host_bg_ = 0u;
        host_mono_transparent_ = true;
        host_clip_enabled_ = host_clip_excludes_inside_ = false;
        host_clip_left_ = host_clip_top_ = host_clip_right_ = host_clip_bottom_ = 0u;
    }
    struct SurfaceState {
        uint32_t base = 0;
        uint32_t pitch_pixels = 0;
        uint32_t pitch_bytes = 0;
        uint32_t width_pixels = 0;
    };
    struct State2d {
        uint32_t src_x = 0, src_y = 0, dst_x = 0, dst_y = 0, width = 0, height = 0;
        uint32_t src_pitch = kFbWidth, dst_pitch = kFbWidth;
        SurfaceState src_surface;
        SurfaceState dst_surface;
        uint16_t fill_color = 0, inv_fg = 0;
        uint32_t control = 0;
        bool backwards = false;
        bool clip_enabled = false;
        bool clip_excludes_inside = false;
        uint32_t clip_left = 0, clip_top = 0, clip_right = 0, clip_bottom = 0;
    };
    struct VramBlitRect {
        uint32_t src_x = 0, src_y = 0, dst_x = 0, dst_y = 0;
        uint32_t width = 0, height = 0;
        bool rtl_btl = false;
    };

    static constexpr uint32_t k2dSource = 0x100000u;
    static constexpr uint32_t k2dDestination = 0x100004u;
    static constexpr uint32_t k2dDimension = 0x100008u;
    static constexpr uint32_t k2dControl = 0x10000Cu;
    static constexpr uint32_t k2dPitch = 0x100010u;
    static constexpr uint32_t k2dForeground = 0x100014u;
    static constexpr uint32_t k2dBackground = 0x100018u;
    static constexpr uint32_t k2dStretchAndFormat = 0x10001Cu;
    static constexpr uint32_t k2dClipTopLeft = 0x10002Cu;
    static constexpr uint32_t k2dClipBottomRight = 0x100030u;
    static constexpr uint32_t k2dMonoPatternLow = 0x100034u;
    static constexpr uint32_t k2dMonoPatternHigh = 0x100038u;
    static constexpr uint32_t k2dWindowWidth = 0x10003Cu;
    static constexpr uint32_t k2dSourceBase = 0x100040u;
    static constexpr uint32_t k2dDestinationBase = 0x100044u;
    static constexpr uint32_t k2dPitchMask = 0x1FFFu;
    static constexpr uint32_t kDdiHostColorBpp = 16u;

    uint32_t R(uint32_t off) const;
    static uint32_t SrcPitchField(uint32_t value) { return value & k2dPitchMask; }
    static uint32_t DstPitchField(uint32_t value) { return (value >> 16) & k2dPitchMask; }
    /* SM501 Databook v1.02 section 4, 2D Source, Destination and
       Dimension register field tables. */
    static uint32_t SourceX(uint32_t value) { return (value >> 16) & 0x0FFFu; }
    static uint32_t SourceY(uint32_t value) { return value & 0x0FFFu; }
    static uint32_t DestinationX(uint32_t value) { return (value >> 16) & 0x1FFFu; }
    static uint32_t DestinationY(uint32_t value) { return value & 0x0FFFu; }
    static uint32_t DimensionX(uint32_t value) { return (value >> 16) & 0x1FFFu; }
    static uint32_t DimensionY(uint32_t value) { return value & 0xFFFFu; }
    /* SM501 Databook v1.02 section 4, 2D Control: Command is bits
       [20:16], H (host colour/monochrome select) is bit 22, and T
       (transparency enable) is bit 8. */
    static uint32_t CommandField(uint32_t value) { return (value >> 16) & 0x1Fu; }
    static bool ColorPatternSelected(uint32_t value) { return (value & (1u << 30)) != 0; }
    static bool DrawingEngineStarted(uint32_t value) { return (value & (1u << 31)) != 0; }
    static bool HostWriteIsMonochrome(uint32_t value) { return (value & (1u << 22)) != 0; }
    static bool TransparencyEnabled(uint32_t value) { return (value & (1u << 8)) != 0; }
    uint32_t DecodePitchField(uint32_t p, uint32_t fallback) const;
    uint32_t DecodeDstPitchPixels() const;
    uint32_t DecodeSrcPitchPixels() const;
    SurfaceState DecodeSurface(bool source, uint32_t cmd) const;
    State2d DecodeState2d(uint32_t cmd) const;
    bool DestinationPixelEnabled(const State2d& state, uint32_t x, uint32_t y) const;
    uint32_t NormalizeFbOffset(uint32_t v) const;
    void FillRect16(const State2d& st, uint16_t color);
    uint16_t DecodeDdiColorRegister(uint32_t off) const;
    void BeginDdiVgxHostDataCommand(uint32_t cmd);
    void CompleteHostDataIfDone();
    void HostDataWritePixel(uint32_t x, uint32_t y, uint16_t p);
    void HostDataAdvanceRow();
    void HostDataMonoByte(uint8_t b);
    uint8_t HostRowByte(uint32_t i) const;
    void FlushHostDataColorRow();
    void HostDataColorByte(uint8_t b);
    void BeginDdiPatternUpload();
    void FinishDdiPatternUpload();
    void HandleDdiPatternDataPortWord(uint32_t v);
    uint16_t PatternPixel565(const State2d& st, uint32_t x, uint32_t y);
    void PatternFillRect16(const State2d& st);
    void HandleDdiVgxDataPortWord(uint32_t v);
    void ExecuteDdiFill(const State2d& st);
    void ExecuteDdiLineDraw(const State2d& st);
    uint32_t SurfaceWidthPixels16(const SurfaceState& s) const;
    uint32_t SurfaceHeightRows(const SurfaceState& s) const;
    VramBlitRect NormalizeVramBlitRect(const State2d& st) const;
    void ExecuteDdiVideoToVideo(const State2d& st);
    void ExecuteDdiVgx2dCommand(uint32_t cmd);

    bool pattern_upload_active_ = false;
    bool pattern_valid_ = false;
    std::vector<uint32_t> pattern_words_;
    bool host_data_active_ = false;
    bool host_data_mono_ = false;
    uint32_t host_dst_x_ = 0;
    uint32_t host_dst_y_ = 0;
    uint32_t host_width_ = 0;
    uint32_t host_height_ = 0;
    uint32_t host_dst_pitch_bytes_ = kFbStride;
    uint32_t host_dst_surface_width_ = kFbWidth;
    uint32_t host_dst_surface_height_ = kFbHeight;
    uint32_t host_dst_base_ = 0;
    uint32_t host_y_ = 0;
    uint32_t host_src_byte_in_row_ = 0;
    uint32_t host_src_bit_offset_ = 0;
    uint32_t host_src_active_bytes_ = 0;
    uint32_t host_src_pitch_bytes_ = 0;
    std::vector<uint8_t> host_row_bytes_;
    uint16_t host_fg_ = 0xFFFFu;
    uint16_t host_bg_ = 0x0000u;
    bool host_mono_transparent_ = true;
    bool host_clip_enabled_ = false;
    bool host_clip_excludes_inside_ = false;
    uint32_t host_clip_left_ = 0;
    uint32_t host_clip_top_ = 0;
    uint32_t host_clip_right_ = 0;
    uint32_t host_clip_bottom_ = 0;
};

} // namespace siemens_mp377
