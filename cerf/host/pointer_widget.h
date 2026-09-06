#pragma once

#define NOMINMAX
#include <windows.h>

#include "../core/service.h"
#include "host_widget.h"

#include <string>
#include <vector>

class PointerSource;

class PointerWidget : public Service, public HostWidget {
public:
    using Service::Service;

    bool ShouldRegister() override;
    void OnReady() override;

    std::wstring WidgetName() const override { return L"Pointing device"; }
    WidgetGroup  Group() const override { return WidgetGroup::InputControl; }
    std::wstring Tooltip() const override;
    void OnPrimaryAction() override;
    bool PrimaryActionOpensMenu() const override;
    std::vector<WidgetMenuItem> BuildMenu() override;
    void DrawIcon(HDC dc, const RECT& box) const override;
    bool PollDirty() override;
    void SaveWidgetState(StateWriter& w) const override;
    void RestoreWidgetState(StateReader& r) override;

private:
    bool AltTapItemVisible() const;
    bool StylusSimItemVisible() const;

    const PointerSource* drawn_source_ = nullptr;  /* UI-thread only */
};
