#define NOMINMAX

#include "host_input_capture.h"

#include "../core/cerf_emulator.h"
#include "../core/log.h"
#include "host_canvas.h"
#include "keyboard_input.h"

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
        case VK_LCONTROL: return VK_CONTROL;  /* RCONTROL is the host key */
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
    if (auto* k = emu_.TryGet<KeyboardInput>())
        k->OnHostKey((uint8_t)NormalizeVk(vk), key_up);
}

void HostInputCapture::Toggle() {
    captured_.store(!captured_.load(std::memory_order_acquire),
                    std::memory_order_release);
    /* The status-bar lock widget reflects this via its PollDirty on the next
       UI tick — no direct poke needed. */
}

void HostInputCapture::SendCtrlAltDel() {
    auto* k = emu_.TryGet<KeyboardInput>();
    if (!k) return;
    k->OnHostKey(VK_CONTROL, false);
    k->OnHostKey(VK_MENU,    false);
    k->OnHostKey(VK_DELETE,  false);
    k->OnHostKey(VK_DELETE,  true);
    k->OnHostKey(VK_MENU,    true);
    k->OnHostKey(VK_CONTROL, true);
}

bool HostInputCapture::OnHookKey(WPARAM wParam, const KBDLLHOOKSTRUCT* k) {
    /* Only ever act while our window is foreground — otherwise the global
       hook would steal Right Ctrl (and captured keys) from other apps. */
    if (!IsForeground()) return false;

    const bool  key_up = (wParam == WM_KEYUP || wParam == WM_SYSKEYUP);
    const DWORD vk      = k->vkCode;

    if (vk == VK_RCONTROL) {
        if (!key_up) {
            rctrl_down_ = true;
            rctrl_used_ = false;
        } else {
            const bool used = rctrl_used_;
            rctrl_down_ = false;
            if (!used) Toggle();      /* a clean tap toggles capture */
        }
        return true;                  /* host key reserved, never to guest */
    }

    if (rctrl_down_ && !key_up) rctrl_used_ = true;

    if (rctrl_down_ && vk == VK_DELETE) {
        if (!key_up) SendCtrlAltDel();
        return true;
    }

    if (captured_.load(std::memory_order_acquire)) {
        if (emu_.Get<HostCanvas>().CurrentTab() == HostCanvas::Tab::Framebuffer)
            ForwardToGuest(vk, key_up);
        return true;                  /* locked in: swallow from host */
    }
    return false;
}
