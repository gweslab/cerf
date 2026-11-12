#include "show_without_activating.h"

#define NOMINMAX
#include <windows.h>

#include <QWindow>

namespace {

LRESULT CALLBACK RefuseActivation(int code, WPARAM wparam, LPARAM lparam) {
    if (code == HCBT_ACTIVATE) return 1;
    return CallNextHookEx(nullptr, code, wparam, lparam);
}

}

void ShowWithoutActivating(QWindow& window) {
    HHOOK hook = SetWindowsHookExW(WH_CBT, RefuseActivation, nullptr, GetCurrentThreadId());
    window.show();
    UnhookWindowsHookEx(hook);
}
