#pragma once

#include <cerfcore/core/service.h>

#include <atomic>
#include <cstdint>

namespace cerffrontend {

class InputCapture : public cerfcore::Service {
public:
    using cerfcore::Service::Service;

    bool IsCaptured() const { return captured_.load(std::memory_order_acquire); }
    void Toggle() { SetCaptured(!IsCaptured()); }
    void SetCaptured(bool on);
    void OnFocusLost();
    void SendCtrlAltDel();
    bool OnHostKey(uint32_t vk, bool key_up);

protected:
    virtual void OnCaptureChanged(bool) {}

private:
    void ForwardToGuest(uint32_t vk, bool key_up);

    std::atomic<bool> captured_{false};
    uint32_t          host_key_down_mask_    = 0;
    uint32_t          host_key_swallow_mask_ = 0;
    bool              host_key_held_         = false;
    bool              host_key_used_         = false;
};

}
