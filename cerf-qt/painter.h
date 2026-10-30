#pragma once

#include <cerfcore/host/widget_icon.h>

#include <cstdint>
#include <memory>
#include <string_view>

namespace cerffrontend {

using Rgb = cerfcore::WidgetRgb;

struct Point {
    int x = 0;
    int y = 0;
};

struct Rect {
    int left   = 0;
    int top    = 0;
    int right  = 0;
    int bottom = 0;

    int  Width() const { return right - left; }
    int  Height() const { return bottom - top; }
    bool Contains(int x, int y) const {
        return x >= left && x < right && y >= top && y < bottom;
    }
    Rect Offset(int dx, int dy) const { return {left + dx, top + dy, right + dx, bottom + dy}; }
    bool operator==(const Rect&) const = default;
};

enum class FontFace : uint8_t { kUi, kMono, kSystem };

struct Font {
    FontFace face = FontFace::kUi;
    int      px   = 0;
    bool     bold = false;
    bool operator==(const Font&) const = default;
};

namespace text {
inline constexpr uint32_t kLeft        = 0;
inline constexpr uint32_t kCenter      = 1u << 0;
inline constexpr uint32_t kTop         = 0;
inline constexpr uint32_t kVCenter     = 1u << 1;
inline constexpr uint32_t kBottom      = 1u << 2;
inline constexpr uint32_t kWordBreak   = 1u << 3;
inline constexpr uint32_t kSingleLine  = 1u << 4;
inline constexpr uint32_t kEndEllipsis = 1u << 5;
inline constexpr uint32_t kEditControl = 1u << 6;
}

struct FontMetrics {
    int line_height     = 0;
    int avg_char_width  = 0;
};

enum class PainterImage : uint8_t { kCerfLogo };

struct GradientStop {
    double  at = 0.0;
    Rgb     color;
    uint8_t alpha = 255;
};

class Painter {
public:
    virtual ~Painter() = default;

    virtual void FillRect(const Rect& r, Rgb color) = 0;
    virtual void BlendRect(const Rect& r, Rgb color, uint8_t alpha) = 0;
    virtual void Rectangle(const Rect& r, Rgb pen, int pen_width, const Rgb* fill) = 0;
    virtual void RoundRect(const Rect& r, int corner_w, int corner_h, Rgb pen, Rgb fill) = 0;
    virtual void Ellipse(const Rect& r, Rgb pen, Rgb fill) = 0;
    virtual void Polyline(const Point* points, int count, Rgb pen, int pen_width) = 0;

    virtual void FillCircleAA(int cx, int cy, int radius, Rgb fill, Rgb rim) = 0;
    virtual void FillPolygonAA(const Point* points, int count, Rgb fill, Rgb rim) = 0;
    virtual void FillRoundRectAA(const Rect& r, int radius, Rgb fill, Rgb rim) = 0;
    virtual void FillRoundRectAlphaAA(const Rect& r, int radius, Rgb fill, uint8_t alpha) = 0;
    virtual void FillGradient(const Rect& r, Point from, Point to, const GradientStop* stops, int count) = 0;

    virtual void DrawTextBox(const Rect& r, std::string_view utf8, const Font& font, Rgb color,
                             uint32_t flags) = 0;
    virtual void DrawTextAt(int x, int y, std::string_view utf8, const Font& font, Rgb color) = 0;
    virtual int  TextHeight(std::string_view utf8, const Font& font, int width,
                            uint32_t flags) = 0;
    virtual int  TextWidth(std::string_view utf8, const Font& font) = 0;
    virtual FontMetrics Metrics(const Font& font) = 0;

    virtual void DrawIcon(const Rect& box, std::string_view stem, int px) = 0;
    virtual void DrawSymbol(const Rect& box, std::string_view stem, int px, Rgb color) = 0;
    virtual void DrawImage(const Rect& dst, PainterImage image, float opacity) = 0;
};

class OffscreenSurface {
public:
    virtual ~OffscreenSurface() = default;

    virtual uint32_t* Bits() = 0;
    virtual int       Width() const = 0;
    virtual int       Height() const = 0;
    virtual Painter&  Paint() = 0;
    virtual void      Flush() = 0;
};

}
