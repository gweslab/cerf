#include "battery_widget.h"

#include "../core/cerf_emulator.h"
#include "../state/state_stream.h"
#include "host_gdiplus.h"

#include <cstdint>

namespace {

/* Host icon-colour banding on the user-facing fill percent. */
constexpr int kLevelHigh = 65;   /* >= -> green  */
constexpr int kLevelLow  = 20;   /* >= -> yellow, else red */

const COLORREF kClrHigh = RGB(78, 201, 90);
const COLORREF kClrLow  = RGB(220, 200, 60);
const COLORREF kClrCrit = RGB(229, 80, 80);

}  /* namespace */

int BatteryWidget::FillPercent() const {
    std::lock_guard<std::mutex> lk(state_mutex_);
    return fill_percent_;
}

bool BatteryWidget::IsOnBattery() const {
    std::lock_guard<std::mutex> lk(state_mutex_);
    return on_battery_;
}

void BatteryWidget::SetOnBattery(bool on_battery) {
    {
        std::lock_guard<std::mutex> lk(state_mutex_);
        on_battery_ = on_battery;
    }
    if (on_change_) on_change_();
}

void BatteryWidget::SetFillPercent(int fill) {
    if (fill < 0)   fill = 0;
    if (fill > 100) fill = 100;
    {
        std::lock_guard<std::mutex> lk(state_mutex_);
        fill_percent_ = fill;
    }
    if (on_change_) on_change_();
}

std::wstring BatteryWidget::Tooltip() const {
    bool on_batt;
    int  fill;
    {
        std::lock_guard<std::mutex> lk(state_mutex_);
        on_batt = on_battery_;
        fill    = fill_percent_;
    }
    const wchar_t* level = fill >= kLevelHigh ? L"High"
                         : fill >= kLevelLow  ? L"Low"
                                              : L"Critical";
    wchar_t buf[96];
    swprintf_s(buf, L"Battery - %s, %d%% (%s)",
               on_batt ? L"on battery" : L"on AC", fill, level);
    return buf;
}

void BatteryWidget::DrawIcon(HDC dc, const RECT& box) const {
    bool on_batt;
    int  fill;
    {
        std::lock_guard<std::mutex> lk(state_mutex_);
        on_batt = on_battery_;
        fill    = fill_percent_;
    }
    const COLORREF lvl = fill >= kLevelHigh ? kClrHigh
                       : fill >= kLevelLow  ? kClrLow
                                            : kClrCrit;

    const int cx = (box.left + box.right) / 2;
    const int cy = (box.top + box.bottom) / 2;
    constexpr int kBodyW = 18, kBodyH = 11;
    RECT body = { cx - kBodyW / 2, cy - kBodyH / 2,
                  cx + kBodyW / 2, cy + kBodyH / 2 };

    HPEN    pen   = CreatePen(PS_SOLID, 1, RGB(170, 170, 180));
    HBRUSH  dark  = CreateSolidBrush(RGB(30, 32, 38));
    HGDIOBJ op    = SelectObject(dc, pen);
    HGDIOBJ ob    = SelectObject(dc, dark);
    Rectangle(dc, body.left, body.top, body.right, body.bottom);

    /* terminal nub on the right */
    RECT nub = { body.right, cy - 2, body.right + 2, cy + 2 };
    HBRUSH nubfill = CreateSolidBrush(RGB(170, 170, 180));
    FillRect(dc, &nub, nubfill);
    DeleteObject(nubfill);

    /* charge fill, proportional, level-coloured */
    const int inner_w = kBodyW - 2;
    const int fw      = inner_w * fill / 100;
    if (fw > 0) {
        RECT fr = { body.left + 1, body.top + 1, body.left + 1 + fw, body.bottom - 1 };
        HBRUSH fb = CreateSolidBrush(lvl);
        FillRect(dc, &fr, fb);
        DeleteObject(fb);
    }

    /* AC: a small charging bolt overlay */
    if (!on_batt) {
        const POINT bolt[] = {
            { cx,     cy - 5 }, { cx - 3, cy + 1 }, { cx,     cy + 1 },
            { cx - 1, cy + 5 }, { cx + 3, cy - 1 }, { cx,     cy - 1 },
        };
        emu_.Get<HostGdiPlus>().FillPolygonAA(
            dc, bolt, (int)(sizeof(bolt) / sizeof(bolt[0])),
            RGB(120, 220, 255), RGB(40, 60, 80));
    }

    SelectObject(dc, ob);
    SelectObject(dc, op);
    DeleteObject(dark);
    DeleteObject(pen);
}

std::vector<WidgetMenuItem> BatteryWidget::BuildMenu() {
    bool on_batt;
    int  fill;
    {
        std::lock_guard<std::mutex> lk(state_mutex_);
        on_batt = on_battery_;
        fill    = fill_percent_;
    }

    std::vector<WidgetMenuItem> items;

    WidgetMenuItem ac;
    ac.label    = L"On battery power";
    ac.checked  = on_batt;
    ac.on_click = [this, on_batt] { SetOnBattery(!on_batt); };
    items.push_back(std::move(ac));

    items.push_back(WidgetMenuItem{});  /* separator */

    WidgetMenuItem level;
    level.label = L"Charge level";
    for (int preset : { 100, 80, 60, 40, 20, 5 }) {
        WidgetMenuItem p;
        wchar_t lbl[16];
        swprintf_s(lbl, L"%d%%", preset);
        p.label    = lbl;
        p.checked  = fill == preset;
        p.on_click = [this, preset] { SetFillPercent(preset); };
        level.submenu.push_back(std::move(p));
    }
    items.push_back(std::move(level));

    return items;
}

bool BatteryWidget::PollDirty() {
    std::lock_guard<std::mutex> lk(state_mutex_);
    const uint8_t on = on_battery_ ? 1u : 0u;
    if (on == last_drawn_on_battery_ && fill_percent_ == last_drawn_fill_) {
        return false;
    }
    last_drawn_on_battery_ = on;
    last_drawn_fill_       = fill_percent_;
    return true;
}

void BatteryWidget::SaveWidgetState(StateWriter& w) const {
    std::lock_guard<std::mutex> lk(state_mutex_);
    w.Write<uint8_t>("on_battery", on_battery_ ? 1u : 0u);
    w.Write<int32_t>("fill_percent", fill_percent_);
}

void BatteryWidget::RestoreWidgetState(StateReader& r) {
    uint8_t on = 0;
    int32_t fill = 100;
    r.Read("on_battery", on);
    r.Read("fill_percent", fill);
    if (fill < 0)   fill = 0;
    if (fill > 100) fill = 100;
    {
        std::lock_guard<std::mutex> lk(state_mutex_);
        on_battery_   = (on != 0u);
        fill_percent_ = fill;
    }
    /* Re-apply onto the owner's hardware model (GPIO/MCU lines), outside the
       lock since the handler re-reads the getters. Pull-based owners have no
       handler and read the restored state live. */
    if (on_change_) on_change_();
}
