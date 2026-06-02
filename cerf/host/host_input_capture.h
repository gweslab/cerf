#pragma once

#include "../core/service.h"

#define NOMINMAX
#include <windows.h>

#include <atomic>
#include <cstdint>

class HostInputCapture : public Service {
public:
    using Service::Service;
    ~HostInputCapture() override;

    /* UI thread only: the LL hook fires on the installing thread, so it
       must be installed (and removed) from HostWindow's UI thread. */
    void AttachUiThread(HWND host_hwnd);
    void DetachUiThread();

    bool IsCaptured() const { return captured_.load(std::memory_order_acquire); }
    void Toggle();
    void SendCtrlAltDel();

    /* Called from the LL hook proc; returns true to swallow the key. */
    bool OnHookKey(WPARAM wParam, const KBDLLHOOKSTRUCT* k);

private:
    bool IsForeground() const;
    void ForwardToGuest(uint32_t vk, bool key_up);

    HHOOK hook_      = nullptr;
    HWND  host_hwnd_ = nullptr;
    std::atomic<bool> captured_{false};
    bool  rctrl_down_ = false;
    bool  rctrl_used_ = false;  /* Right Ctrl used as a modifier this press */
};
