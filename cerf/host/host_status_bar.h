#pragma once

#include "../core/service.h"

#define NOMINMAX
#include <windows.h>
#include <commctrl.h>

#include <string>
#include <utility>
#include <vector>

class HostWidget;

class HostStatusBar : public Service {
public:
    using Service::Service;
    ~HostStatusBar() override;

    void OnReady() override;

    static constexpr int kHeight = 24;
    int  Height() const { return kHeight; }

    void CreateOn(HWND parent, const RECT& rect);
    void Reposition(const RECT& rect);

    HWND Hwnd() const { return hwnd_; }

private:
    static LRESULT CALLBACK WndProcStatic(HWND, UINT, WPARAM, LPARAM);
    LRESULT WndProc(HWND, UINT, WPARAM, LPARAM);

    bool Relayout(const std::vector<HostWidget*>& ordered);  /* true if boxes changed */
    void RebuildTooltips();
    void UpdateTipText(size_t idx, std::wstring text);       /* flicker-free live refresh */
    HostWidget* WidgetAt(int x) const;

    HWND    hwnd_       = nullptr;
    HWND    tip_hwnd_   = nullptr;
    HBRUSH  bg_brush_   = nullptr;
    HPEN    sep_pen_    = nullptr;

    /* UI-thread only. Right-to-left layout: InputControl-group widgets pin to
       the right edge and always show; device widgets fill the space to their
       left, leftmost dropping off into the Actions menu on overflow. */
    std::vector<std::pair<HostWidget*, RECT>> layout_;
    std::vector<std::wstring>                 tip_texts_;   /* backs TTTOOLINFO ptrs */
    size_t                                    tip_count_ = 0;
};
