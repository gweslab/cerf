#include "host_widget.h"

#include <cstdint>

namespace {
constexpr int      kGlowTicks = 3;                 /* ~300 ms at the 100 ms tick */
constexpr COLORREF kRxColor   = RGB(78, 201, 90);  /* green */
constexpr COLORREF kTxColor   = RGB(229, 80, 80);  /* red */
constexpr int      kDotR      = 3;
constexpr BYTE     kDisabledAlpha = 150;           /* gray blended over a disabled icon */

void DimRect(HDC dc, const RECT& box) {
    HDC mdc = CreateCompatibleDC(dc);
    if (!mdc) return;
    BITMAPINFO bi = {};
    bi.bmiHeader.biSize        = sizeof(BITMAPINFOHEADER);
    bi.bmiHeader.biWidth       = 1;
    bi.bmiHeader.biHeight      = 1;
    bi.bmiHeader.biPlanes      = 1;
    bi.bmiHeader.biBitCount    = 32;
    bi.bmiHeader.biCompression = BI_RGB;
    void* bits = nullptr;
    HBITMAP dib = CreateDIBSection(mdc, &bi, DIB_RGB_COLORS, &bits, nullptr, 0);
    if (dib && bits) {
        *static_cast<uint32_t*>(bits) = 0x00202020u;   /* bar-background gray */
        HGDIOBJ ob = SelectObject(mdc, dib);
        BLENDFUNCTION bf = { AC_SRC_OVER, 0, kDisabledAlpha, 0 };
        AlphaBlend(dc, box.left, box.top, box.right - box.left,
                   box.bottom - box.top, mdc, 0, 0, 1, 1, bf);
        SelectObject(mdc, ob);
        DeleteObject(dib);
    }
    DeleteDC(mdc);
}
}  /* namespace */

bool HostWidget::SampleActivity() {
    if (rx_pending_.exchange(false, std::memory_order_relaxed)) rx_glow_ = kGlowTicks;
    else if (rx_glow_ > 0)                                      --rx_glow_;
    if (tx_pending_.exchange(false, std::memory_order_relaxed)) tx_glow_ = kGlowTicks;
    else if (tx_glow_ > 0)                                      --tx_glow_;

    const bool now     = (rx_glow_ > 0) || (tx_glow_ > 0);
    const bool repaint = now || was_active_;
    was_active_ = now;
    return repaint;
}

void HostWidget::DrawComposited(HDC dc, const RECT& box) {
    DrawIcon(dc, box);

    if (!IsEnabled()) {
        DimRect(dc, box);
        return;   /* disabled => no activity dots */
    }

    auto dot = [&](COLORREF c, int cx, int cy) {
        HBRUSH  br = CreateSolidBrush(c);
        HPEN    pn = CreatePen(PS_SOLID, 1, RGB(20, 20, 20));
        HGDIOBJ ob = SelectObject(dc, br);
        HGDIOBJ op = SelectObject(dc, pn);
        Ellipse(dc, cx - kDotR, cy - kDotR, cx + kDotR + 1, cy + kDotR + 1);
        SelectObject(dc, ob);
        SelectObject(dc, op);
        DeleteObject(br);
        DeleteObject(pn);
    };
    if (rx_glow_ > 0) dot(kRxColor, box.left  + kDotR + 1, box.bottom - kDotR - 2);
    if (tx_glow_ > 0) dot(kTxColor, box.right - kDotR - 2, box.bottom - kDotR - 2);
}
