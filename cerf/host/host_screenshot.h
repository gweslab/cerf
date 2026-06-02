#pragma once

#include "../core/service.h"

#define NOMINMAX
#include <windows.h>

#include <cstdint>

/* Save / copy the 1:1 guest framebuffer image. Reads the live surface from
   HostCanvas; both entry points run on the UI thread (menu WM_COMMAND),
   same thread as the canvas render, so the surface read needs no lock. */

class HostScreenshot : public Service {
public:
    using Service::Service;
    ~HostScreenshot() override;

    void OnReady() override;

    void Save();   /* -> <exe_dir>\screenshots\<device>_<timestamp>.png */
    void Copy();   /* -> clipboard as CF_DIB */

private:
    ULONG_PTR gdiplus_token_ = 0;
};
