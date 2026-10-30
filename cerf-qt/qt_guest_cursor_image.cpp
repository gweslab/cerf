#include "qt_guest_cursor_image.h"

#include "guest_cursor_pixels.h"

#include <cerfcore/peripherals/cerf_virt/cerf_virt_cursor.h>

#include <vector>

namespace {

constexpr QRgb kBlack = 0xFF000000u;
constexpr QRgb kWhite = 0xFFFFFFFFu;

QPoint SourcePixel(int x, int y, int w, int h, int quarter) {
    switch (quarter & 3) {
        case 1:  return {y, h - 1 - x};
        case 2:  return {w - 1 - x, h - 1 - y};
        case 3:  return {w - 1 - y, x};
        default: return {x, y};
    }
}

}

QImage TurnedGuestCursor(const QImage& image, int quarter, int scale_x, int scale_y) {
    const int  w      = image.width();
    const int  h      = image.height();
    const bool turned = (quarter & 1) != 0;
    QImage     out((turned ? h : w) * scale_x, (turned ? w : h) * scale_y, QImage::Format_ARGB32);
    for (int y = 0; y < out.height(); ++y) {
        QRgb* line = reinterpret_cast<QRgb*>(out.scanLine(y));
        for (int x = 0; x < out.width(); ++x) line[x] = image.pixel(SourcePixel(x / scale_x, y / scale_y, w, h, quarter));
    }
    return out;
}

QPoint TurnedGuestHotspot(QPoint hotspot, QSize size, int quarter, int scale_x, int scale_y) {
    const int w = size.width();
    const int h = size.height();
    QPoint    turned;
    switch (quarter & 3) {
        case 1:  turned = {h - 1 - hotspot.y(), hotspot.x()}; break;
        case 2:  turned = {w - 1 - hotspot.x(), h - 1 - hotspot.y()}; break;
        case 3:  turned = {hotspot.y(), w - 1 - hotspot.x()}; break;
        default: turned = hotspot; break;
    }
    return {turned.x() * scale_x, turned.y() * scale_y};
}

/* Wine dlls/winex11.drv/mouse.c create_xlib_monochrome_cursor: an inverted pixel is
   drawn black, with a white pixel at (+1, +1). */
QImage GuestCursorImage(const cerfcore::GuestCursorShape& s) {
    const int cx = static_cast<int>(s.cx);
    const int cy = static_cast<int>(s.cy);
    if (cx <= 0 || cy <= 0) return QImage();

    const std::vector<cerffrontend::CursorPixel> pixels = cerffrontend::GuestCursorPixels::Decode(s);
    QImage image(cx, cy, QImage::Format_ARGB32);
    image.fill(0u);
    for (int y = 0; y < cy; ++y) {
        for (int x = 0; x < cx; ++x) {
            switch (pixels[static_cast<size_t>(y) * cx + x]) {
                case cerffrontend::CursorPixel::kTransparent: break;
                case cerffrontend::CursorPixel::kBlack:
                case cerffrontend::CursorPixel::kInvert:      image.setPixel(x, y, kBlack); break;
                case cerffrontend::CursorPixel::kWhite:       image.setPixel(x, y, kWhite); break;
            }
        }
    }
    for (int y = 0; y + 1 < cy; ++y)
        for (int x = 0; x + 1 < cx; ++x)
            if (pixels[static_cast<size_t>(y) * cx + x] == cerffrontend::CursorPixel::kInvert)
                image.setPixel(x + 1, y + 1, kWhite);
    return image;
}
