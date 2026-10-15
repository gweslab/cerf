#pragma once

#include "host_widget.h"

#include <functional>
#include <mutex>
#include <string>
#include <vector>

class CerfEmulator;

/* Reusable cross-board battery status-bar widget (charge level + AC/battery
   toggle, icon/tooltip/menu). Owner holds one as a member and reads the getters
   to drive its hardware model. */
class BatteryWidget : public HostWidget {
public:
    /* emu is held to resolve HostGdiPlus when DrawIcon renders the bolt. */
    explicit BatteryWidget(CerfEmulator& emu) : emu_(emu) {}

    /* Read on the JIT/peripheral thread, mutated on the UI thread via the menu. */
    int  FillPercent() const;   /* 0..100, 100 = full */
    bool IsOnBattery() const;   /* true = on battery, false = on AC */

    /* Invoked (outside the state lock) after any menu-driven state change, so an
       owner can push the new state onto its hardware model (e.g. AC GPIO pins). */
    void SetChangeHandler(std::function<void()> cb) { on_change_ = std::move(cb); }

    std::wstring WidgetName() const override { return L"Battery"; }
    std::wstring MenuLabel() const override;
    WidgetGroup  Group() const override { return WidgetGroup::Power; }
    std::wstring Tooltip() const override;
    void DrawIcon(HDC dc, const RECT& box) const override;
    std::vector<WidgetMenuItem> BuildMenu() override;
    bool PollDirty() override;

    void SaveWidgetState(StateWriter& w) const override;
    void RestoreWidgetState(StateReader& r) override;

private:
    void SetOnBattery(bool on_battery);
    void SetFillPercent(int fill);

    mutable std::mutex state_mutex_;
    std::function<void()> on_change_;
    bool on_battery_   = false;   /* default: on AC */
    int  fill_percent_ = 100;     /* default: full  */

    /* UI-thread only: last-drawn state so PollDirty repaints only on change. */
    uint8_t last_drawn_on_battery_ = 0xFF;
    int     last_drawn_fill_       = -1;

    CerfEmulator& emu_;
};
