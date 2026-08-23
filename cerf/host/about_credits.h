#pragma once

#include "../core/service.h"

#define NOMINMAX
#include <windows.h>

#include <string>

class AboutCredits : public Service {
public:
    using Service::Service;

    void OnReady() override;

    int  Height(UINT dpi) const;
    void Create(HWND parent, HFONT font, int x, int y, int w, UINT dpi);

private:
    static LRESULT CALLBACK WndProcStatic(HWND, UINT, WPARAM, LPARAM);
    LRESULT WndProc(HWND, UINT, WPARAM, LPARAM);

    std::wstring Contributors() const;
    void Measure(HWND hwnd);
    void Paint(HWND hwnd, HDC dc);

    int S(int v) const;

    HFONT        font_      = nullptr;
    UINT         dpi_       = USER_DEFAULT_SCREEN_DPI;
    std::wstring text_;
    std::wstring cycle_;
    int          cycle_w_   = 0;
    int          text_h_    = 0;
    bool         scrolling_ = false;
    ULONGLONG    start_ms_  = 0;
};
