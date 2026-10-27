#include "widget_icon_painter.h"

#include <cerfcore/core/cerf_emulator.h>

#include <algorithm>
#include <iterator>
#include <variant>

namespace cerffrontend {

REGISTER_SERVICE(WidgetIconPainter);

namespace {

constexpr Rgb kOutline{150, 150, 160};

void Segment(Painter& p, Point a, Point b, Rgb pen, int width) {
    const Point line[2] = {a, b};
    p.Polyline(line, 2, pen, width);
}

}

void WidgetIconPainter::Paint(Painter& p, const Rect& box, const cerfcore::WidgetIcon& icon) {
    std::visit([&](const auto& i) { Draw(p, box, i); }, icon);
}

void WidgetIconPainter::Draw(Painter& p, const Rect& box, const cerfcore::ResourceIcon& icon) {
    p.DrawIcon(box, icon.name, std::min(box.Width(), box.Height()) - 4);
}

void WidgetIconPainter::Draw(Painter& p, const Rect& box, const cerfcore::ChipIcon&) {
    const int  cx   = (box.left + box.right) / 2;
    const int  cy   = (box.top + box.bottom) / 2;
    const Rect body = {cx - 8, cy - 6, cx + 8, cy + 6};
    const Rgb  fill{40, 44, 52};
    p.Rectangle(body, kOutline, 1, &fill);
    for (int i = -1; i <= 1; ++i) {
        const int px = cx + i * 5;
        Segment(p, {px, body.top - 2}, {px, body.top}, kOutline, 1);
        Segment(p, {px, body.bottom - 1}, {px, body.bottom + 1}, kOutline, 1);
    }
}

void WidgetIconPainter::Draw(Painter& p, const Rect& box, const cerfcore::HardDiskIcon&) {
    const int cx = (box.left + box.right) / 2;
    const int cy = (box.top + box.bottom) / 2;
    p.RoundRect({cx - 8, cy - 6, cx + 8, cy + 6}, 3, 3, kOutline, Rgb{48, 52, 60});
    p.Ellipse({cx - 2, cy - 2, cx + 3, cy + 3}, kOutline, Rgb{170, 175, 185});
}

void WidgetIconPainter::Draw(Painter& p, const Rect& box, const cerfcore::LedIcon& icon) {
    const int cx = (box.left + box.right) / 2;
    const int cy = (box.top + box.bottom) / 2;
    const int r  = icon.radius;

    if (icon.vibrate) {
        const Rgb pen{200, 160, 80};
        for (int s = 1; s <= 2; ++s) {
            const int   xr      = cx + r + 1 + s * 2;
            const Point right[] = {{xr, cy - 3}, {xr + 2, cy}, {xr, cy + 3}};
            p.Polyline(right, 3, pen, 1);
            const int   xl     = cx - r - 1 - s * 2;
            const Point left[] = {{xl, cy - 3}, {xl - 2, cy}, {xl, cy + 3}};
            p.Polyline(left, 3, pen, 1);
        }
    }
    p.FillCircleAA(cx, cy, r, icon.fill, icon.rim);
}

void WidgetIconPainter::Draw(Painter& p, const Rect& box, const cerfcore::LedGridIcon& icon) {
    constexpr int kCell = 4, kGap = 1;
    const int grid_w = 4 * kCell + 3 * kGap;
    const int grid_h = 2 * kCell + 1 * kGap;
    const int x0     = (box.left + box.right) / 2 - grid_w / 2;
    const int y0     = (box.top + box.bottom) / 2 - grid_h / 2;
    for (int i = 0; i < 8; ++i) {
        const bool on  = ((icon.bits >> (7 - i)) & 1u) != 0u;
        const int  x   = x0 + (i % 4) * (kCell + kGap);
        const int  y   = y0 + (i / 4) * (kCell + kGap);
        const Rgb  fill = on ? icon.lit : icon.dark;
        p.Rectangle({x, y, x + kCell, y + kCell}, icon.outline, 1, &fill);
    }
}

void WidgetIconPainter::Draw(Painter& p, const Rect& box, const cerfcore::PowerInputIcon& icon) {
    const Rgb outline = icon.failed ? Rgb{245, 105, 105} : Rgb{155, 165, 175};
    const Rgb fill    = icon.failed ? Rgb{105, 28, 28} : Rgb{38, 48, 58};
    const int cx      = (box.left + box.right) / 2;
    const int cy      = (box.top + box.bottom) / 2;
    p.Rectangle({cx - 5, cy - 5, cx + 5, cy + 5}, outline, 2, &fill);
    Segment(p, {cx - 2, cy - 9}, {cx - 2, cy - 5}, outline, 2);
    Segment(p, {cx + 2, cy - 9}, {cx + 2, cy - 5}, outline, 2);
    Segment(p, {cx, cy + 5}, {cx, cy + 9}, outline, 2);
}

void WidgetIconPainter::Draw(Painter& p, const Rect& box, const cerfcore::BatteryIcon& icon) {
    const Rgb level = icon.level == cerfcore::BatteryLevel::kHigh  ? Rgb{78, 201, 90}
                      : icon.level == cerfcore::BatteryLevel::kLow ? Rgb{220, 200, 60}
                                                                   : Rgb{229, 80, 80};
    const int     cx = (box.left + box.right) / 2;
    const int     cy = (box.top + box.bottom) / 2;
    constexpr int kBodyW = 18, kBodyH = 11;
    const Rect body = {cx - kBodyW / 2, cy - kBodyH / 2, cx + kBodyW / 2, cy + kBodyH / 2};
    const Rgb  frame{170, 170, 180};
    const Rgb  dark{30, 32, 38};
    p.Rectangle(body, frame, 1, &dark);
    p.FillRect({body.right, cy - 2, body.right + 2, cy + 2}, frame);

    const int fw = (kBodyW - 2) * icon.fill_percent / 100;
    if (fw > 0) p.FillRect({body.left + 1, body.top + 1, body.left + 1 + fw, body.bottom - 1}, level);

    if (!icon.on_battery) {
        const Point bolt[] = {
            {cx, cy - 5},     {cx - 3, cy + 1}, {cx, cy + 1},
            {cx - 1, cy + 5}, {cx + 3, cy - 1}, {cx, cy - 1},
        };
        p.FillPolygonAA(bolt, static_cast<int>(std::size(bolt)), Rgb{120, 220, 255},
                        Rgb{40, 60, 80});
    }
}

void WidgetIconPainter::Draw(Painter& p, const Rect& box, const cerfcore::FolderIcon& icon) {
    const Rgb   color = icon.enabled ? Rgb{232, 196, 92} : Rgb{224, 224, 224};
    const int   cx    = (box.left + box.right) / 2;
    const int   cy    = (box.top + box.bottom) / 2;
    const Point folder[] = {
        {cx - 8, cy + 6}, {cx - 8, cy - 6}, {cx - 2, cy - 6},
        {cx, cy - 3},     {cx + 8, cy - 3}, {cx + 8, cy + 6},
    };
    p.FillPolygonAA(folder, static_cast<int>(std::size(folder)), color, color);
}

}
