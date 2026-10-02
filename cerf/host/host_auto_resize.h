#pragma once

#define NOMINMAX
#include <windows.h>

#include "../core/service.h"
#include "host_widget.h"

#include <atomic>
#include <cstdint>

/* Guest-additions auto-resize policy + the Guest Additions status-bar
   widget. When auto-resize is enabled, a user window resize publishes the
   new canvas size to the guest re-mode channel (CerfVirtResize). */
class HostAutoResize : public Service, public HostWidget {
public:
    using Service::Service;
    ~HostAutoResize() override;

    bool ShouldRegister() override;
    void OnReady() override;

    bool Enabled() const { return enabled_.load(std::memory_order_acquire); }

    /* UI thread, on WM_EXITSIZEMOVE. No-op unless enabled. */
    void OnUserResizeEnd(uint32_t canvas_w, uint32_t canvas_h);

    std::wstring WidgetName() const override { return L"Guest Additions"; }
    WidgetGroup  Group() const override { return WidgetGroup::GuestAdditions; }
    std::wstring Tooltip() const override;
    bool TryPrimaryAction() override;
    std::vector<WidgetMenuItem> BuildMenu() override;
    void DrawIcon(HDC dc, const RECT& box) const override;
    bool PollDirty() override;

private:
    void Toggle();

    std::atomic<bool> enabled_{true};
    uint32_t last_w_      = 0;   /* last published size; UI-thread only */
    uint32_t last_h_      = 0;
    bool  last_drawn_on_  = false;
};
