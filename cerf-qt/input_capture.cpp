#include "input_capture.h"

#include "frontend_window.h"
#include "host_key_binding.h"
#include "host_virtual_keys.h"

#include <cerfcore/core/cerf_emulator.h>
#include <cerfcore/host/emulation_pause.h>
#include <cerfcore/host/keyboard_router.h>

namespace cerffrontend {

namespace {

uint32_t NormalizeVk(uint32_t vk) {
    switch (vk) {
        case kVkLShift:
        case kVkRShift:   return kVkShift;
        case kVkLControl:
        case kVkRControl: return kVkControl;
        case kVkLMenu:
        case kVkRMenu:    return kVkMenu;
        default:          return vk;
    }
}

}

void InputCapture::SetCaptured(bool on) {
    captured_.store(on, std::memory_order_release);
    OnCaptureChanged(on);
}

void InputCapture::OnFocusLost() {
    host_key_down_mask_    = 0;
    host_key_swallow_mask_ = 0;
    host_key_held_         = false;
    host_key_used_         = false;
    SetCaptured(false);
}

void InputCapture::ForwardToGuest(uint32_t vk, bool key_up) {
    emu_.Get<cerfcore::KeyboardRouter>().OnHostKey(static_cast<uint8_t>(NormalizeVk(vk)), key_up);
}

void InputCapture::SendCtrlAltDel() {
    auto& k = emu_.Get<cerfcore::KeyboardRouter>();
    k.OnHostKey(kVkControl, false);
    k.OnHostKey(kVkMenu, false);
    k.OnHostKey(kVkDelete, false);
    k.OnHostKey(kVkDelete, true);
    k.OnHostKey(kVkMenu, true);
    k.OnHostKey(kVkControl, true);
}

bool InputCapture::OnHostKey(uint32_t vk, bool key_up) {
    auto&     host_key = emu_.Get<HostKeyBinding>();
    const int member   = host_key.IndexOf(vk);
    if (member >= 0) {
        const uint32_t bit = 1u << member;
        bool           swallow_from_host;
        if (!key_up) {
            if (host_key_down_mask_ & bit) {
                swallow_from_host = (host_key_swallow_mask_ & bit) != 0;
            } else {
                swallow_from_host = IsCaptured();
                host_key_down_mask_ |= bit;
                if (swallow_from_host) host_key_swallow_mask_ |= bit;
                else                   host_key_swallow_mask_ &= ~bit;
            }
            if (!host_key_held_ && host_key_down_mask_ == host_key.AllMembersDownMask()) {
                host_key_held_ = true;
                host_key_used_ = false;
            }
        } else {
            swallow_from_host = (host_key_swallow_mask_ & bit) != 0;
            host_key_down_mask_ &= ~bit;
            host_key_swallow_mask_ &= ~bit;
            const bool used = host_key_used_;
            const bool held = host_key_held_;
            host_key_held_  = false;
            if (held && !used) Toggle();
        }
        return swallow_from_host;
    }

    if (host_key_held_ && !key_up) host_key_used_ = true;

    if (host_key_held_ && vk == kVkDelete) {
        if (!key_up) SendCtrlAltDel();
        return true;
    }
    if (host_key_held_ && vk == kVkP) {
        if (!key_up) emu_.Get<cerfcore::EmulationPause>().Toggle();
        return true;
    }
    if (host_key_held_ && vk == kVkF) {
        if (!key_up) emu_.Get<FrontendWindow>().ToggleFullscreen();
        return true;
    }

    if (IsCaptured()) {
        if (emu_.Get<FrontendWindow>().CurrentTab() == FrontendWindow::Tab::Framebuffer)
            ForwardToGuest(vk, key_up);
        return true;
    }
    return false;
}

}
