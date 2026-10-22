#define NOMINMAX

#include "host_dpi.h"

#include <cerfcore/core/cerf_emulator.h>
#include <cerfcore/core/log.h>

REGISTER_SERVICE(HostDpi);

void HostDpi::OnReady() {
    HMODULE u32 = GetModuleHandleW(L"user32.dll");
    get_dpi_for_window_ =
        (GetDpiForWindow_t)GetProcAddress(u32, "GetDpiForWindow");
    adjust_for_dpi_ =
        (AdjustWindowRectExForDpi_t)GetProcAddress(u32, "AdjustWindowRectExForDpi");
    spi_for_dpi_ =
        (SystemParametersInfoForDpi_t)GetProcAddress(u32, "SystemParametersInfoForDpi");
    if (HMODULE shcore = LoadLibraryW(L"shcore.dll"))
        get_dpi_for_monitor_ =
            (GetDpiForMonitor_t)GetProcAddress(shcore, "GetDpiForMonitor");
}

UINT HostDpi::ForPrimaryMonitor() const {
    constexpr int kMdtEffectiveDpi = 0;
    if (get_dpi_for_monitor_) {
        const HMONITOR primary = MonitorFromPoint(POINT{0, 0}, MONITOR_DEFAULTTOPRIMARY);
        UINT dpi_x = 0, dpi_y = 0;
        const HRESULT hr = get_dpi_for_monitor_(primary, kMdtEffectiveDpi, &dpi_x, &dpi_y);
        if (SUCCEEDED(hr)) return dpi_x;
        LOG(Caution, "HostDpi: GetDpiForMonitor failed (hr=0x%08lX), using the system DPI\n",
            (unsigned long)hr);
    }
    return ForWindow(nullptr);
}

UINT HostDpi::ForWindow(HWND h) const {
    if (h && get_dpi_for_window_) return get_dpi_for_window_(h);
    HDC dc = GetDC(h);
    if (!dc) return USER_DEFAULT_SCREEN_DPI;
    const UINT dpi = (UINT)GetDeviceCaps(dc, LOGPIXELSX);
    ReleaseDC(h, dc);
    return dpi;
}

BOOL HostDpi::AdjustForDpi(RECT& r, DWORD style, BOOL menu, DWORD ex,
                           UINT dpi) const {
    if (adjust_for_dpi_) return adjust_for_dpi_(&r, style, menu, ex, dpi);
    return AdjustWindowRectEx(&r, style, menu, ex);
}

BOOL HostDpi::NonClientMetricsForDpi(NONCLIENTMETRICSW& ncm, UINT dpi) const {
    ncm.cbSize = sizeof(ncm);
    if (spi_for_dpi_)
        return spi_for_dpi_(SPI_GETNONCLIENTMETRICS, sizeof(ncm), &ncm, 0, dpi);
    return SystemParametersInfoW(SPI_GETNONCLIENTMETRICS, sizeof(ncm), &ncm, 0);
}
