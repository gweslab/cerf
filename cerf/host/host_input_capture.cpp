#define NOMINMAX

#include "host_input_capture.h"

#include "../core/cerf_emulator.h"
#include "../core/log.h"
#include "emulation_pause.h"
#include "host_canvas.h"
#include "host_key_binding.h"
#include "host_key_prompt.h"
#include "host_window.h"
#include "keyboard_router.h"

REGISTER_SERVICE(HostInputCapture);

namespace {

/* LL keyboard hooks fire on the thread that installed them; each
   CerfEmulator has its own UI thread, so this thread_local routes the
   context-less C callback to the right instance with no cross-instance
   state (approved Win32-callback exception). */
thread_local HostInputCapture* t_active = nullptr;

LRESULT CALLBACK LlKeyboardProc(int code, WPARAM wParam, LPARAM lParam) {
    if (code == HC_ACTION && t_active) {
        auto* k = reinterpret_cast<const KBDLLHOOKSTRUCT*>(lParam);
        if (t_active->OnHookKey(wParam, k)) return 1;  /* swallow */
    }
    return CallNextHookEx(nullptr, code, wParam, lParam);
}

uint32_t NormalizeVk(uint32_t vk) {
    switch (vk) {
        case VK_LSHIFT:
        case VK_RSHIFT:   return VK_SHIFT;
        case VK_LCONTROL:
        case VK_RCONTROL: return VK_CONTROL;
        case VK_LMENU:
        case VK_RMENU:    return VK_MENU;
        default:          return vk;
    }
}

}  /* namespace */

HostInputCapture::~HostInputCapture() { DetachUiThread(); }

void HostInputCapture::AttachUiThread(HWND host_hwnd) {
    host_hwnd_ = host_hwnd;
    t_active = this;
    hook_ = SetWindowsHookExW(WH_KEYBOARD_LL, &LlKeyboardProc,
                              GetModuleHandleW(nullptr), 0);
    if (!hook_)
        LOG(Caution, "HostInputCapture: SetWindowsHookEx failed (gle=%lu)\n",
            GetLastError());
}

void HostInputCapture::DetachUiThread() {
    if (hook_) { UnhookWindowsHookEx(hook_); hook_ = nullptr; }
    if (t_active == this) t_active = nullptr;
}

bool HostInputCapture::IsForeground() const {
    return host_hwnd_ && GetForegroundWindow() == host_hwnd_;
}

void HostInputCapture::ForwardToGuest(uint32_t vk, bool key_up) {
    emu_.Get<KeyboardRouter>().OnHostKey((uint8_t)NormalizeVk(vk), key_up);
}

void HostInputCapture::Toggle() {
    SetCaptured(!captured_.load(std::memory_order_acquire));
}

void HostInputCapture::SetCaptured(bool on) {
    captured_.store(on, std::memory_order_release);
    /* The status-bar lock widget reflects this via its PollDirty on the next
       UI tick - no direct poke needed. */
}

void HostInputCapture::OnFocusLost() {
    host_key_down_mask_ = 0;
    host_key_swallow_mask_ = 0;
    host_key_held_ = false;
    host_key_used_ = false;
    SetCaptured(false);
}

void HostInputCapture::SendCtrlAltDel() {
    auto& k = emu_.Get<KeyboardRouter>();
    k.OnHostKey(VK_CONTROL, false);
    k.OnHostKey(VK_MENU,    false);
    k.OnHostKey(VK_DELETE,  false);
    k.OnHostKey(VK_DELETE,  true);
    k.OnHostKey(VK_MENU,    true);
    k.OnHostKey(VK_CONTROL, true);
}

bool HostInputCapture::OnHookKey(WPARAM wParam, const KBDLLHOOKSTRUCT* k) {
    if (!IsForeground()) return false;

    const bool  key_up = (wParam == WM_KEYUP || wParam == WM_SYSKEYUP);
    const DWORD vk      = k->vkCode;

    /* A HwScreen key prompt (boot prompt, restore-failure hold) owns the
       keyboard while it is showing. */
    if (!key_up) {
        if (auto* kp = emu_.TryGet<HostKeyPrompt>(); kp && kp->Armed()) {
            kp->OnKey(vk);
            return true;
        }
    }

    auto& host_key = emu_.Get<HostKeyBinding>();
    const int member = host_key.IndexOf(vk);
    if (member >= 0) {
        const uint32_t bit = 1u << member;
        bool swallow_from_host;
        if (!key_up) {
            if (host_key_down_mask_ & bit) {
                swallow_from_host = (host_key_swallow_mask_ & bit) != 0;
            } else {
                swallow_from_host = captured_.load(std::memory_order_acquire);
                host_key_down_mask_ |= bit;
                if (swallow_from_host) host_key_swallow_mask_ |= bit;
                else                   host_key_swallow_mask_ &= ~bit;
            }
            if (!host_key_held_ &&
                host_key_down_mask_ == host_key.AllMembersDownMask()) {
                host_key_held_ = true;
                host_key_used_ = false;
            }
        } else {
            swallow_from_host = (host_key_swallow_mask_ & bit) != 0;
            host_key_down_mask_ &= ~bit;
            host_key_swallow_mask_ &= ~bit;
            const bool used = host_key_used_;
            const bool held = host_key_held_;
            host_key_held_ = false;
            if (held && !used) Toggle();
        }
        return swallow_from_host;
    }

    if (host_key_held_ && !key_up) host_key_used_ = true;

    if (host_key_held_ && vk == VK_DELETE) {
        if (!key_up) SendCtrlAltDel();
        return true;
    }

    if (host_key_held_ && vk == 'P') {
        if (!key_up) emu_.Get<EmulationPause>().Toggle();
        return true;
    }

    if (host_key_held_ && vk == 'F') {
        if (!key_up) emu_.Get<HostWindow>().ToggleFullscreen();
        return true;
    }

    if (captured_.load(std::memory_order_acquire)) {
        if (emu_.Get<HostCanvas>().CurrentTab() == HostCanvas::Tab::Framebuffer)
            ForwardToGuest(vk, key_up);
        return true;                  /* locked in: swallow from host */
    }
    return false;
}
