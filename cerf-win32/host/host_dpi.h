#pragma once

#include <cerfcore/core/service.h>

#define NOMINMAX
#include <windows.h>

/* MS Learn: GetDpiForWindow / AdjustWindowRectExForDpi - minimum supported
   client Windows 10, version 1607; user32.dll. */
class HostDpi : public cerfcore::Service {
public:
    using cerfcore::Service::Service;
    void OnReady() override;

    UINT ForWindow(HWND h) const;
    UINT ForPrimaryMonitor() const;
    BOOL AdjustForDpi(RECT& r, DWORD style, BOOL menu, DWORD ex, UINT dpi) const;
    BOOL NonClientMetricsForDpi(NONCLIENTMETRICSW& ncm, UINT dpi) const;

private:
    using GetDpiForWindow_t          = UINT (WINAPI*)(HWND);
    using AdjustWindowRectExForDpi_t = BOOL (WINAPI*)(LPRECT, DWORD, BOOL, DWORD, UINT);
    using SystemParametersInfoForDpi_t = BOOL (WINAPI*)(UINT, UINT, PVOID, UINT, UINT);
    using GetDpiForMonitor_t         = HRESULT (WINAPI*)(HMONITOR, int, UINT*, UINT*);

    GetDpiForWindow_t            get_dpi_for_window_  = nullptr;
    AdjustWindowRectExForDpi_t   adjust_for_dpi_      = nullptr;
    SystemParametersInfoForDpi_t spi_for_dpi_         = nullptr;
    GetDpiForMonitor_t           get_dpi_for_monitor_ = nullptr;
};
