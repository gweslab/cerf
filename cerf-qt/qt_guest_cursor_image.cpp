#include "qt_guest_cursor_image.h"

#include "guest_cursor_pixels.h"

#include <cerfcore/peripherals/cerf_virt/cerf_virt_cursor.h>

#include <vector>

namespace {

constexpr QRgb kBlack = 0xFF000000u;
constexpr QRgb kWhite = 0xFFFFFFFFu;

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
