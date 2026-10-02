#pragma once

#include "../core/service.h"
#include "host_widget.h"

#include <string>
#include <vector>

class KeyboardInput;

/* Board-agnostic status-bar keyboard widget: registers whenever the board
   provides a KeyboardMap. Left- or right-click opens a menu whose first item
   is "See keyboard mapping" (the host-keyboard replica dialog); a board may add
   hardware-hotkey sections via KeyboardHotkeyMenu. */
class KeyboardWidget : public Service, public HostWidget {
public:
    using Service::Service;

    bool ShouldRegister() override;
    void OnReady() override;

    std::wstring WidgetName() const override { return L"Keyboard"; }
    WidgetGroup  Group() const override { return WidgetGroup::InputControl; }
    std::wstring Tooltip() const override;
    void DrawIcon(HDC dc, const RECT& box) const override;
    std::vector<WidgetMenuItem> BuildMenu() override;
    bool PollDirty() override;

    void SaveWidgetState(StateWriter& w) const override;
    void RestoreWidgetState(StateReader& r) override;

private:
    const KeyboardInput* drawn_source_ = nullptr;   /* UI-thread only */
};
