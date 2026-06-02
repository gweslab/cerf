#pragma once

#include "../core/service.h"

#define NOMINMAX
#include <windows.h>

/* Dark menu bar/popups via undocumented uxtheme dark-mode ordinals + the
   undocumented UAH menu messages — best-effort, no-ops on an OS that
   doesn't send them. */

class HostDarkMode : public Service {
public:
    using Service::Service;
    ~HostDarkMode() override;

    void Init();                 /* once: load ordinals, app dark mode */
    void ApplyToWindow(HWND h);  /* per top-level + child window */

    /* Returns true (and fills `out`) when it fully handled the message. */
    bool HandleMessage(HWND hwnd, UINT msg, WPARAM wp, LPARAM lp, LRESULT& out);

private:
    void EnsureResources();

    bool   inited_ = false;
    HBRUSH bar_brush_ = nullptr;
    HBRUSH hot_brush_ = nullptr;
    HBRUSH sel_brush_ = nullptr;
    HFONT  menu_font_ = nullptr;
};
