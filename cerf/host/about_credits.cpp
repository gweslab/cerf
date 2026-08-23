#define NOMINMAX
#include "about_credits.h"

#include "../core/cerf_emulator.h"
#include "../core/string_utils.h"
#include "host_dark_mode.h"
#include "host_resource.h"

REGISTER_SERVICE(AboutCredits);

namespace {

constexpr wchar_t kClass[]    = L"CerfAboutCredits";
constexpr wchar_t kResource[] = L"ABOUT_CONTRIBUTORS";
constexpr wchar_t kSeparator[] = L"   \x2022   ";

constexpr wchar_t kHeader[] = L"Thanks to project contributors:";

constexpr wchar_t kEveryoneElse[] = L"everyone else who helped";

constexpr int kHeaderDip      = 18;
constexpr int kHeaderGapDip   = 0;
constexpr int kMarqueeDip     = 22;
constexpr int kTotalDip       = kHeaderDip + kHeaderGapDip + kMarqueeDip;
constexpr int kSpeedDipPerSec = 34;
constexpr int kFrameMs        = 16;
constexpr UINT_PTR kTimerId   = 1;

}

int AboutCredits::S(int v) const {
    return MulDiv(v, (int)dpi_, USER_DEFAULT_SCREEN_DPI);
}

int AboutCredits::Height(UINT dpi) const {
    return MulDiv(kTotalDip, (int)dpi, USER_DEFAULT_SCREEN_DPI);
}

void AboutCredits::OnReady() {
    WNDCLASSEXW wc = {};
    wc.cbSize        = sizeof(wc);
    wc.lpfnWndProc   = &AboutCredits::WndProcStatic;
    wc.hInstance     = GetModuleHandleW(nullptr);
    wc.hCursor       = LoadCursorW(nullptr, IDC_ARROW);
    wc.lpszClassName = kClass;
    RegisterClassExW(&wc);
}

std::wstring AboutCredits::Contributors() const {
    std::span<const uint8_t> bytes = emu_.Get<HostResource>().Bytes(kResource);
    if (bytes.empty()) return {};
    const std::string utf8(reinterpret_cast<const char*>(bytes.data()),
                           bytes.size());
    const std::wstring list = Utf8ToWide(utf8.c_str());

    std::wstring out;
    size_t pos = 0;
    while (pos < list.size()) {
        size_t end = list.find(L'\n', pos);
        if (end == std::wstring::npos) end = list.size();
        std::wstring name = list.substr(pos, end - pos);
        while (!name.empty() && (name.back() == L'\r' || name.back() == L' '))
            name.pop_back();
        if (!name.empty()) {
            if (!out.empty()) out += kSeparator;
            out += name;
        }
        pos = end + 1;
    }
    if (!out.empty()) out += kSeparator;
    out += kEveryoneElse;
    return out;
}

void AboutCredits::Measure(HWND hwnd) {
    cycle_ = text_.empty() ? std::wstring() : text_ + kSeparator;

    HDC     dc  = GetDC(hwnd);
    HGDIOBJ old = SelectObject(dc, font_);
    SIZE full = { 0, 0 }, once = { 0, 0 };
    GetTextExtentPoint32W(dc, cycle_.c_str(), (int)cycle_.size(), &full);
    GetTextExtentPoint32W(dc, text_.c_str(), (int)text_.size(), &once);
    SelectObject(dc, old);
    ReleaseDC(hwnd, dc);

    cycle_w_ = full.cx;
    text_h_  = once.cy;

    RECT rc = { 0, 0, 0, 0 };
    GetClientRect(hwnd, &rc);
    scrolling_ = cycle_w_ > 0 && once.cx > rc.right - rc.left;

    if (scrolling_) SetTimer(hwnd, kTimerId, kFrameMs, nullptr);
    else            KillTimer(hwnd, kTimerId);
}

void AboutCredits::Paint(HWND hwnd, HDC dc) {
    RECT rc = { 0, 0, 0, 0 };
    GetClientRect(hwnd, &rc);
    const int w = rc.right - rc.left, h = rc.bottom - rc.top;
    if (w <= 0 || h <= 0) return;

    auto& dm = emu_.Get<HostDarkMode>();
    const COLORREF bg = dm.IsDark() ? dm.BgColor() : GetSysColor(COLOR_BTNFACE);
    const COLORREF fg = dm.IsDark() ? dm.TextColor()
                                    : GetSysColor(COLOR_BTNTEXT);

    HDC     mem = CreateCompatibleDC(dc);
    HBITMAP bmp = CreateCompatibleBitmap(dc, w, h);
    HGDIOBJ ob  = SelectObject(mem, bmp);

    HBRUSH brush = CreateSolidBrush(bg);
    RECT fill = { 0, 0, w, h };
    FillRect(mem, &fill, brush);
    DeleteObject(brush);

    HGDIOBJ of = SelectObject(mem, font_);
    SetBkMode(mem, TRANSPARENT);
    SetTextColor(mem, fg);

    const int y = (h - text_h_) / 2;
    int x = 0;
    if (scrolling_) {
        const ULONGLONG elapsed = GetTickCount64() - start_ms_;
        const ULONGLONG travel  = elapsed * (ULONGLONG)S(kSpeedDipPerSec) / 1000;
        x = -(int)(travel % (ULONGLONG)cycle_w_);
    }
    const std::wstring& draw = scrolling_ ? cycle_ : text_;
    TextOutW(mem, x, y, draw.c_str(), (int)draw.size());
    if (scrolling_)
        TextOutW(mem, x + cycle_w_, y, draw.c_str(), (int)draw.size());

    SelectObject(mem, of);
    BitBlt(dc, 0, 0, w, h, mem, 0, 0, SRCCOPY);
    SelectObject(mem, ob);
    DeleteObject(bmp);
    DeleteDC(mem);
}

void AboutCredits::Create(HWND parent, HFONT font, int x, int y, int w,
                          UINT dpi) {
    dpi_      = dpi;
    font_     = font;
    text_     = Contributors();
    start_ms_ = GetTickCount64();

    HINSTANCE inst = GetModuleHandleW(nullptr);
    auto mk = [&](const wchar_t* cls, const wchar_t* txt, DWORD style,
                  int cy, int ch) {
        return CreateWindowExW(0, cls, txt, WS_CHILD | WS_VISIBLE | style,
                               x, cy, w, ch, parent, nullptr, inst, this);
    };

    int cy = y;
    mk(L"STATIC", kHeader, SS_LEFT | SS_NOPREFIX, cy, S(kHeaderDip));
    cy += S(kHeaderDip) + S(kHeaderGapDip);

    HWND marquee = mk(kClass, nullptr, 0, cy, S(kMarqueeDip));

    Measure(marquee);
}

LRESULT AboutCredits::WndProc(HWND hwnd, UINT msg, WPARAM wp, LPARAM lp) {
    switch (msg) {
        case WM_PAINT: {
            PAINTSTRUCT ps;
            HDC dc = BeginPaint(hwnd, &ps);
            Paint(hwnd, dc);
            EndPaint(hwnd, &ps);
            return 0;
        }

        case WM_TIMER:
            InvalidateRect(hwnd, nullptr, FALSE);
            return 0;

        case WM_SETFONT:
            font_ = (HFONT)wp;
            Measure(hwnd);
            InvalidateRect(hwnd, nullptr, FALSE);
            return 0;

        case WM_ERASEBKGND:
            return 1;

        case WM_NCDESTROY:
            KillTimer(hwnd, kTimerId);
            break;
    }
    return DefWindowProcW(hwnd, msg, wp, lp);
}

LRESULT CALLBACK AboutCredits::WndProcStatic(HWND hwnd, UINT msg, WPARAM wp,
                                             LPARAM lp) {
    if (msg == WM_NCCREATE) {
        auto* cs = reinterpret_cast<CREATESTRUCTW*>(lp);
        SetWindowLongPtrW(hwnd, GWLP_USERDATA,
                          reinterpret_cast<LONG_PTR>(cs->lpCreateParams));
    }
    auto* self = reinterpret_cast<AboutCredits*>(
        GetWindowLongPtrW(hwnd, GWLP_USERDATA));
    if (self) return self->WndProc(hwnd, msg, wp, lp);
    return DefWindowProcW(hwnd, msg, wp, lp);
}
