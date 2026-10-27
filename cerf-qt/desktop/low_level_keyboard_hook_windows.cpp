#define NOMINMAX

#include "low_level_keyboard_hook.h"

#include <cerfcore/core/log.h>

#include <windows.h>

namespace cerffrontend {

namespace {

thread_local LowLevelKeyboardHook* t_active = nullptr;

LRESULT CALLBACK LlKeyboardProc(int code, WPARAM wParam, LPARAM lParam) {
    if (code == HC_ACTION && t_active) {
        const auto* k = reinterpret_cast<const KBDLLHOOKSTRUCT*>(lParam);
        if (t_active->OnKey(k->vkCode, wParam == WM_KEYUP || wParam == WM_SYSKEYUP)) return 1;
    }
    return CallNextHookEx(nullptr, code, wParam, lParam);
}

}

void LowLevelKeyboardHook::Install(Handler handler) {
    handler_ = std::move(handler);
    t_active = this;
    hook_    = SetWindowsHookExW(WH_KEYBOARD_LL, &LlKeyboardProc, GetModuleHandleW(nullptr), 0);
    if (hook_) return;
    LOG(Caution, "LowLevelKeyboardHook: SetWindowsHookEx failed (gle=%lu)\n", GetLastError());
    t_active = nullptr;
}

void LowLevelKeyboardHook::Remove() {
    if (hook_) {
        UnhookWindowsHookEx(static_cast<HHOOK>(hook_));
        hook_ = nullptr;
    }
    if (t_active == this) t_active = nullptr;
}

}
