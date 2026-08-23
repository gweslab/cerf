#define NOMINMAX
#include "host_gdiplus.h"

#include "../core/cerf_emulator.h"
#include "host_resource.h"

#include <objbase.h>
#include <gdiplus.h>
#include <vector>

REGISTER_SERVICE(HostGdiPlus);

void HostGdiPlus::OnReady() {
    Gdiplus::GdiplusStartupInput in;
    Gdiplus::GdiplusStartup(&gdiplus_token_, &in, nullptr);
}

HostGdiPlus::~HostGdiPlus() {
    if (gdiplus_token_) Gdiplus::GdiplusShutdown(gdiplus_token_);
}

void HostGdiPlus::FillCircleAA(HDC dc, int cx, int cy, int r, COLORREF fill,
                               COLORREF rim) {
    Gdiplus::Graphics g(dc);
    g.SetSmoothingMode(Gdiplus::SmoothingModeAntiAlias);
    g.SetPixelOffsetMode(Gdiplus::PixelOffsetModeHalf);

    /* Inset the path by 0.5px so the 1px rim stroke stays inside the r radius. */
    const Gdiplus::REAL x = (Gdiplus::REAL)(cx - r) + 0.5f;
    const Gdiplus::REAL y = (Gdiplus::REAL)(cy - r) + 0.5f;
    const Gdiplus::REAL d = (Gdiplus::REAL)(2 * r) - 1.0f;

    Gdiplus::SolidBrush brush(
        Gdiplus::Color(GetRValue(fill), GetGValue(fill), GetBValue(fill)));
    g.FillEllipse(&brush, x, y, d, d);

    Gdiplus::Pen pen(
        Gdiplus::Color(GetRValue(rim), GetGValue(rim), GetBValue(rim)), 1.0f);
    g.DrawEllipse(&pen, x, y, d, d);
}

void HostGdiPlus::FillPolygonAA(HDC dc, const POINT* pts, int count,
                                COLORREF fill, COLORREF rim) {
    Gdiplus::Graphics g(dc);
    g.SetSmoothingMode(Gdiplus::SmoothingModeAntiAlias);
    g.SetPixelOffsetMode(Gdiplus::PixelOffsetModeHalf);

    std::vector<Gdiplus::PointF> p((size_t)count);
    for (int i = 0; i < count; ++i)
        p[(size_t)i] = Gdiplus::PointF((Gdiplus::REAL)pts[i].x,
                                       (Gdiplus::REAL)pts[i].y);

    Gdiplus::SolidBrush brush(
        Gdiplus::Color(GetRValue(fill), GetGValue(fill), GetBValue(fill)));
    g.FillPolygon(&brush, p.data(), count);

    Gdiplus::Pen pen(
        Gdiplus::Color(GetRValue(rim), GetGValue(rim), GetBValue(rim)), 1.0f);
    g.DrawPolygon(&pen, p.data(), count);
}

Gdiplus::Bitmap* HostGdiPlus::DecodeResourcePng(const wchar_t* name) {
    std::span<const uint8_t> bytes = emu_.Get<HostResource>().Bytes(name);
    if (bytes.empty()) return nullptr;
    const SIZE_T sz = bytes.size();

    HGLOBAL hg = GlobalAlloc(GMEM_MOVEABLE, sz);
    if (!hg) return nullptr;
    if (void* p = GlobalLock(hg)) { memcpy(p, bytes.data(), sz); GlobalUnlock(hg); }
    IStream* stm = nullptr;
    if (CreateStreamOnHGlobal(hg, TRUE, &stm) != S_OK) { GlobalFree(hg); return nullptr; }
    Gdiplus::Bitmap* bmp = Gdiplus::Bitmap::FromStream(stm);
    stm->Release();  /* fDeleteOnRelease=TRUE frees hg */
    if (bmp && bmp->GetLastStatus() != Gdiplus::Ok) { delete bmp; return nullptr; }
    return bmp;
}
