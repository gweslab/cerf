#include <cerffrontend/hw_screen_renderer.h>

#include <cerffrontend/boot_bar.h>
#include <cerffrontend/boot_screen.h>
#include <cerffrontend/surface_factory.h>

#include <cerfcore/core/cerf_emulator.h>
#include <cerfcore/core/utf16.h>
#include <cerfcore/host/hw_screen.h>

#include <algorithm>
#include <cstring>
#include <string_view>

namespace cerffrontend {

REGISTER_SERVICE(HwScreenRenderer);

namespace {

constexpr int kEdgeMarginPx = 1;
constexpr Rgb kLogText{205, 205, 205};
constexpr Rgb kErrorText{255, 110, 110};
constexpr Rgb kWarnText{235, 210, 90};

constexpr int kFontHeightSmall      = 13;
constexpr int kFontHeightRegular    = 15;
constexpr int kSmallTierThresholdPx = 480;

bool ContainsCI(std::string_view hay, std::string_view needle) {
    if (needle.empty() || needle.size() > hay.size()) return false;
    for (size_t i = 0; i + needle.size() <= hay.size(); ++i) {
        size_t j = 0;
        for (; j < needle.size(); ++j) {
            char a = hay[i + j];
            if (a >= 'A' && a <= 'Z') a = static_cast<char>(a - 'A' + 'a');
            if (a != needle[j]) break;
        }
        if (j == needle.size()) return true;
    }
    return false;
}

Rgb ClassifyLineColor(std::string_view line) {
    if (ContainsCI(line, "abort") || ContainsCI(line, "fail") || ContainsCI(line, "error") ||
        ContainsCI(line, "exception"))
        return kErrorText;
    if (ContainsCI(line, "warning")) return kWarnText;
    return kLogText;
}

}

void HwScreenRenderer::RenderInto(uint32_t* dib_bgra32, uint32_t width, uint32_t height, int dpi) {
    std::vector<std::string> snapshot;
    const uint64_t           gen = emu_.Get<cerfcore::HwScreen>().Snapshot(snapshot);

    if (!bg_ || bg_->Width() != static_cast<int>(width) || bg_->Height() != static_cast<int>(height)) {
        bg_       = emu_.Get<SurfaceFactory>().Create(static_cast<int>(width), static_cast<int>(height));
        bg_valid_ = false;
    }
    if (dpi != dpi_) {
        dpi_      = dpi;
        bg_valid_ = false;
    }

    if (!bg_valid_ || gen != bg_gen_) {
        std::memset(bg_->Bits(), 0, static_cast<size_t>(width) * height * 4u);
        Painter& p = bg_->Paint();
        emu_.Get<BootScreen>().DrawWatermark(p, width, height);
        DrawLog(p, width, height, snapshot);
        bg_->Flush();
        bg_gen_   = gen;
        bg_valid_ = true;
    }

    std::memcpy(dib_bgra32, bg_->Bits(), static_cast<size_t>(width) * height * 4u);
    emu_.Get<BootBar>().RenderInto(dib_bgra32, width, height, dpi_);
}

void HwScreenRenderer::DrawLog(Painter& p, uint32_t width, uint32_t height,
                               const std::vector<std::string>& snapshot) {
    const uint32_t threshold  = static_cast<uint32_t>(ScaleForDpi(kSmallTierThresholdPx, dpi_));
    const bool     small_tier = width < threshold || height < threshold;
    const Font font{FontFace::kMono,
                    ScaleForDpi(small_tier ? kFontHeightSmall : kFontHeightRegular, dpi_), true};

    const FontMetrics fm = p.Metrics(font);
    if (fm.line_height <= 0 || fm.avg_char_width <= 0) return;

    const int edge       = ScaleForDpi(kEdgeMarginPx, dpi_);
    const int avail_h    = static_cast<int>(height) - 2 * edge;
    const int avail_w    = static_cast<int>(width) - 2 * edge;
    const int max_lines  = avail_h > 0 ? avail_h / fm.line_height : 0;
    const int chars_wide = avail_w > 0 ? avail_w / fm.avg_char_width : 0;
    if (max_lines <= 0 || chars_wide <= 0) return;

    struct Chunk {
        std::string text;
        Rgb         color;
    };
    std::vector<Chunk> wrapped;
    wrapped.reserve(snapshot.size());
    for (const std::string& line : snapshot) {
        const Rgb            color = ClassifyLineColor(line);
        const std::u16string wide  = cerfcore::Utf8ToUtf16(line);
        if (wide.empty()) {
            wrapped.push_back({std::string(), color});
            continue;
        }
        size_t pos = 0;
        while (pos < wide.size()) {
            size_t take = std::min(static_cast<size_t>(chars_wide), wide.size() - pos);
            if (take > 1 && pos + take < wide.size() && cerfcore::IsHighSurrogate(wide[pos + take - 1]))
                --take;
            wrapped.push_back({cerfcore::Utf16ToUtf8(wide.substr(pos, take)), color});
            pos += take;
        }
    }

    const int total = static_cast<int>(wrapped.size());
    const int start = total > max_lines ? total - max_lines : 0;
    int       y     = edge;
    for (int i = start; i < total; ++i) {
        p.DrawTextAt(edge, y, wrapped[static_cast<size_t>(i)].text, font,
                     wrapped[static_cast<size_t>(i)].color);
        y += fm.line_height;
    }
}

}
