#pragma once

#include "../core/service.h"

#define NOMINMAX
#include <windows.h>

namespace Gdiplus { class Bitmap; }

/* The host's GDI+ facility: owns the process GDI+ token and the GDI+-backed
   operations host code shares. Plain GDI cannot anti-alias. */
class HostGdiPlus : public Service {
public:
    using Service::Service;
    ~HostGdiPlus() override;

    void OnReady() override;

    /* Filled circle of radius r at (cx, cy) with a 1px rim, anti-aliased. */
    void FillCircleAA(HDC dc, int cx, int cy, int r, COLORREF fill, COLORREF rim);

    /* Filled polygon with a 1px rim, anti-aliased. Pass rim == fill for none. */
    void FillPolygonAA(HDC dc, const POINT* pts, int count, COLORREF fill,
                       COLORREF rim);

    void FillRoundRectAA(HDC dc, const RECT& r, int radius, COLORREF fill,
                         COLORREF rim);
    void FillRoundRectAlphaAA(HDC dc, const RECT& r, int radius, COLORREF fill,
                              BYTE alpha);

    /* Decode an RT_RCDATA PNG resource to a GDI+ bitmap; caller owns it. */
    Gdiplus::Bitmap* DecodeResourcePng(const wchar_t* name);

private:
    ULONG_PTR gdiplus_token_ = 0;
};
