#pragma once

#include "../core/service.h"
#include "notification_stack.h"

#define NOMINMAX
#include <windows.h>

#include <cstdint>
#include <string>
#include <vector>

class NotificationOverlay : public Service {
public:
    using Service::Service;
    ~NotificationOverlay() override;

    void RenderInto(HWND canvas, HDC dc, int dib_w, int dib_h);
    bool HitTest(int x, int y, uint32_t& id) const;

private:
    struct Placed {
        uint32_t         id = 0;
        NotificationKind kind = NotificationKind::Warning;
        bool             more = false;
        RECT             box{};
        RECT             title_rc{};
        RECT             body_rc{};
        std::wstring     title;
        std::wstring     body;
    };

    void Relayout(HDC dc, int w, int h, UINT dpi);
    void Draw(HDC dc);
    void EnsureFonts(int px);
    int  MeasureText(HDC dc, HFONT font, const std::wstring& text, int width) const;

    std::vector<NotificationCard> cards_;
    std::vector<Placed>           placed_;
    uint64_t gen_     = ~0ull;
    int      w_       = 0;
    int      h_       = 0;
    UINT     dpi_     = 0;
    bool     compact_ = false;
    int      radius_  = 0;
    int      shadow_  = 0;
    int      font_px_ = 0;
    HFONT    bold_    = nullptr;
    HFONT    regular_ = nullptr;
};
