#define NOMINMAX

#include "siemens_mp377_sm501.h"
#include "siemens_mp377_sm501_video.h"

#include "../../peripherals/peripheral_base.h"
#include "../../boards/board_context.h"
#include "../../boards/siemens_mp377/siemens_mp377_id.h"
#include "../../core/byte_order.h"
#include "../../core/cerf_emulator.h"
#include "../../host/frame_renderer.h"
#include "../../host/panel_frame_renderer.h"
#include "../../lcd/lcd_pixel_expand.h"

#include <algorithm>
#include <array>
#include <cstdint>
#include <optional>

namespace {

using siemens_mp377::kFbHeight;
using siemens_mp377::kFbWidth;
using siemens_mp377::kSm501FbBytes;
using siemens_mp377::Sm501FbOffsetToPa;

void BuildRgb565ToXrgbLut(std::array<uint32_t, 65536>& lut) {
    for (uint32_t p = 0; p < 65536u; ++p) {
        const uint32_t r = ((p >> 11) & 0x1Fu) << 3;
        const uint32_t g = ((p >> 5) & 0x3Fu) << 2;
        const uint32_t b = (p & 0x1Fu) << 3;
        lut[p] = lcd_pixel::PackXrgb(r, g, b);
    }
}

class SiemensMp377Sm501Renderer : public PanelFrameRenderer {
public:
    using PanelFrameRenderer::PanelFrameRenderer;

    bool ShouldRegister() override {
        auto* bd = emu_.TryGet<BoardContext>();
        return bd && bd->GetBoardId() == BoardId::SiemensMp377;
    }

    void OnReady() override { BuildRgb565ToXrgbLut(rgb565_to_xrgb_); }

    bool HasFrame() override {
        if (latch_.Latched()) return true;
        auto& video = emu_.Get<siemens_mp377::SiemensMp377Sm501Video>();
        const auto scanout = ResolveScanout(video);
        if (!scanout) return false;
        const size_t bytes = static_cast<size_t>(scanout->pitch) * scanout->height;
        return latch_.ProbeAndLatch(video.Vram() + scanout->offset, bytes);
    }

    void RenderInto(uint32_t* dib, uint32_t host_w, uint32_t host_h) override {
        if (!dib || host_w == 0 || host_h == 0) return;
        auto& video = emu_.Get<siemens_mp377::SiemensMp377Sm501Video>();
        const auto scanout = ResolveScanout(video);
        if (!scanout) return;
        const uint8_t* vram = video.Vram();
        const uint8_t* base = vram + scanout->offset;
        const uint32_t fb_w = std::min(scanout->width, host_w);
        const uint32_t fb_h = std::min(scanout->height, host_h);

        for (uint32_t y = 0; y < fb_h; ++y) {
            const uint8_t* srow = base + static_cast<size_t>(y) * scanout->pitch;
            uint32_t* drow = dib + static_cast<size_t>(y) * host_w;
            for (uint32_t x = 0; x < fb_w; ++x) {
                const uint32_t i = x * scanout->bytes_per_pixel;
                if (scanout->bytes_per_pixel == 1u) {
                    drow[x] = 0xFF000000u | (video.DisplayPaletteEntry(srow[i]) & 0x00FFFFFFu);
                } else if (scanout->bytes_per_pixel == 2u) {
                    drow[x] = rgb565_to_xrgb_[cerf::le::U16(srow, i)];
                } else {
                    drow[x] = 0xFF000000u | cerf::le::U24(srow, i);
                }
            }
            OverlayCursorLine(video, drow, fb_w, y, vram);
        }
    }

    std::optional<FbLayout> GetFbLayout() override {
        auto& video = emu_.Get<siemens_mp377::SiemensMp377Sm501Video>();
        const auto scanout = ResolveScanout(video);
        if (!scanout) return std::nullopt;
        const uint32_t bpp = scanout->bytes_per_pixel * 8u;
        return FbLayout{Sm501FbOffsetToPa(scanout->offset), scanout->pitch, bpp, bpp == 16u};
    }

    void PresentedSize(uint32_t& w, uint32_t& h) override {
        w = 0u;
        h = 0u;
        auto& video = emu_.Get<siemens_mp377::SiemensMp377Sm501Video>();
        w = video.DisplayWidth();
        h = video.DisplayHeight();
        /* SM501 Databook v1.02, Panel Graphics Control register table:
           panel timing registers have undefined reset values. */
        if (!w) w = siemens_mp377::Mp377PanelWidth(siemens_mp377::kMp377HwiPanelProfile);
        if (!h) h = siemens_mp377::Mp377PanelHeight(siemens_mp377::kMp377HwiPanelProfile);
    }

private:
    struct Scanout {
        uint32_t offset;
        uint32_t pitch;
        uint32_t width;
        uint32_t height;
        uint32_t bytes_per_pixel;
    };

    static std::optional<Scanout> ResolveScanout(siemens_mp377::SiemensMp377Sm501Video& video) {
        /* SM501 Databook v1.02 section 5, Panel/CRT Graphics Control and
           FB Address, FB Offset, Horizontal Total and Vertical Total. */
        const uint32_t control = video.DisplayControl();
        if ((control & (1u << 2u)) == 0u) return std::nullopt;
        const uint32_t format = control & 3u;
        if (format == 3u) return std::nullopt;
        const uint32_t bytes_per_pixel = 1u << format;
        const uint32_t offset = video.DisplayFbOffset();
        const uint32_t pitch = video.DisplayPitchBytes();
        uint32_t width = video.DisplayWidth();
        uint32_t height = video.DisplayHeight();
        /* SM501 Databook v1.02, Panel Horizontal/Vertical Total register tables;
           siemens_mp377_v1040 nk.exe sub_80446E14. */
        if (!width) width = siemens_mp377::kMp377HwiPanel.width;
        if (!height) height = siemens_mp377::kMp377HwiPanel.height;
        if (offset >= kSm501FbBytes || pitch == 0u || width == 0u || height == 0u) return std::nullopt;
        const uint64_t row_bytes = static_cast<uint64_t>(width) * bytes_per_pixel;
        const uint64_t end = static_cast<uint64_t>(offset) + static_cast<uint64_t>(height - 1u) * pitch + row_bytes;
        if (row_bytes > pitch || end > kSm501FbBytes) return std::nullopt;
        return Scanout{offset, pitch, width, height, bytes_per_pixel};
    }

    void OverlayCursorLine(siemens_mp377::SiemensMp377Sm501Video& video, uint32_t* row,
                           uint32_t width, uint32_t y, const uint8_t* vram) {
        const uint32_t cursor_address = video.DisplayCursorAddress();
        if ((cursor_address & 0x80000000u) == 0u) return;
        const uint32_t location = video.DisplayCursorLocation();
        const uint32_t cursor_x = location & 0x7FFu;
        const uint32_t cursor_y = (location >> 16u) & 0x7FFu;
        if (y < cursor_y || y >= cursor_y + 64u || cursor_x >= width) return;
        const uint32_t base = cursor_address & 0x03FFFFF0u;
        const uint32_t source_row = base + (y - cursor_y) * 16u;
        if (source_row + 16u > kSm501FbBytes) return;
        const uint32_t colors12 = video.DisplayCursorColors12();
        const uint16_t colors[3] = {static_cast<uint16_t>(colors12), static_cast<uint16_t>(colors12 >> 16u),
                                    static_cast<uint16_t>(video.DisplayCursorColor3())};
        for (uint32_t x = 0u; x < 64u && cursor_x + x < width; ++x) {
            const uint8_t packed = vram[source_row + x / 4u];
            const uint8_t index = static_cast<uint8_t>((packed >> ((x & 3u) * 2u)) & 3u);
            if (index != 0u) row[cursor_x + x] = rgb565_to_xrgb_[colors[index - 1u]];
        }
    }

    std::array<uint32_t, 65536> rgb565_to_xrgb_{};
};

} // namespace

REGISTER_SERVICE_AS(SiemensMp377Sm501Renderer, PanelFrameRenderer);
