#define NOMINMAX
#define _CRT_SECURE_NO_WARNINGS
#include "win32_thunks.h"
#include "callbacks_marshal.h"
#include "../log.h"
#include <commctrl.h>
#include <dwmapi.h>
#pragma comment(lib, "comctl32")
#pragma comment(lib, "dwmapi")

/* Static member definitions for callback infrastructure */
std::map<HWND, uint32_t> Win32Thunks::hwnd_wndproc_map;
std::map<UINT_PTR, uint32_t> Win32Thunks::arm_timer_callbacks;
std::map<HWND, uint32_t> Win32Thunks::hwnd_dlgproc_map;
uint32_t Win32Thunks::pending_arm_dlgproc = 0;
std::map<HWND, uint32_t> Win32Thunks::hwnd_wce_style_map;
std::map<HWND, uint32_t> Win32Thunks::hwnd_wce_exstyle_map;
thread_local uint32_t Win32Thunks::tls_pending_wce_style = 0;
thread_local uint32_t Win32Thunks::tls_pending_wce_exstyle = 0;
INT_PTR Win32Thunks::modal_dlg_result = 0;
bool Win32Thunks::modal_dlg_ended = false;
Win32Thunks* Win32Thunks::s_instance = nullptr;
std::set<HWND> Win32Thunks::captionok_hwnds;
thread_local HWND Win32Thunks::tls_paint_hwnd = NULL;

LRESULT CALLBACK Win32Thunks::EmuWndProc(HWND hwnd, UINT msg, WPARAM wParam, LPARAM lParam) {
    if (!s_instance || !t_ctx || !t_ctx->callback_executor) {
        return DefWindowProcW(hwnd, msg, wParam, lParam);
    }

    auto it = hwnd_wndproc_map.find(hwnd);
    if (it == hwnd_wndproc_map.end()) {
        /* During CreateWindow, HWND is not yet in the map.
           Look up the ARM WndProc from the window class name and auto-register. */
        wchar_t cls_name[256] = {};
        GetClassNameW(hwnd, cls_name, 256);
        auto cls_it = s_instance->arm_wndprocs.find(cls_name);
        if (cls_it != s_instance->arm_wndprocs.end()) {
            hwnd_wndproc_map[hwnd] = cls_it->second;
            it = hwnd_wndproc_map.find(hwnd);
        } else {
            if (msg == WM_CREATE || msg == WM_NCCREATE) {
                LOG(API, "[API] EmuWndProc: MISS class='%ls' msg=0x%04X hwnd=0x%p -> DefWindowProc\n",
                    cls_name, msg, hwnd);
            }
            return DefWindowProcW(hwnd, msg, wParam, lParam);
        }
    }

    /* One-time deferred arrange fix for SysListView32. */
    if (msg == WM_PAINT && !GetPropW(hwnd, L"CerfLVArr")) {
        wchar_t cls_chk[64] = {};
        GetClassNameW(hwnd, cls_chk, 64);
        if (wcsstr(cls_chk, L"SysListView32")) {
            int count = (int)::SendMessageW(hwnd, 0x1004 /* LVM_GETITEMCOUNT */, 0, 0);
            if (count > 0) {
                SetPropW(hwnd, L"CerfLVArr", (HANDLE)1);
                LOG(API, "[API] SysListView32 first WM_PAINT: %d items, sending LVM_ARRANGE\n", count);
                ::SendMessageW(hwnd, 0x1016 /* LVM_ARRANGE */, 0, 0);
            }
        }
    }

    /* Messages with native pointer lParams need marshaling.
       For messages we can't marshal, use DefWindowProcW. */
    LPARAM native_lParam = lParam;
    MarshalCallbackExecutor executor = s_instance->callback_executor;
    uint32_t arm_wndproc = it->second;
    LRESULT marshal_result = 0;

    /* WM_NCCALCSIZE: compute WinCE non-client area for top-level captioned windows.
       Since we create top-level WinCE windows as WS_POPUP (no native frame),
       we must manually define the NC area to match WinCE metrics (1px border + caption). */
    if (msg == WM_NCCALCSIZE) {
        auto sit = hwnd_wce_style_map.find(hwnd);
        if (sit != hwnd_wce_style_map.end()) {
            uint32_t ws = sit->second;
            bool has_caption = (ws & WS_CAPTION) == WS_CAPTION;
            bool has_border = (ws & WS_BORDER) != 0;
            if (has_caption || has_border) {
                int border = 1;
                int caption = has_caption ? GetSystemMetrics(SM_CYCAPTION) : 0;
                if (wParam) {
                    NCCALCSIZE_PARAMS* ncp = (NCCALCSIZE_PARAMS*)lParam;
                    ncp->rgrc[0].left += border;
                    ncp->rgrc[0].top += border + caption;
                    ncp->rgrc[0].right -= border;
                    ncp->rgrc[0].bottom -= border;
                } else {
                    RECT* rc = (RECT*)lParam;
                    rc->left += border;
                    rc->top += border + caption;
                    rc->right -= border;
                    rc->bottom -= border;
                }
                return 0;
            }
        }
        return DefWindowProcW(hwnd, msg, wParam, lParam);
    }

    switch (msg) {
    /* Messages with native 64-bit pointers — route to DefWindowProcW */
    case WM_GETMINMAXINFO:
    case WM_NCDESTROY:
    case WM_SETICON:
    case WM_GETICON:
    case WM_COPYDATA:
    case WM_DEVICECHANGE:
    case WM_POWERBROADCAST:
    case WM_INPUT:
    case WM_NCPAINT:
    case 0x90: case 0x91: case 0x92: case 0x93: case 0x94: case 0x95:
    case WM_ENTERMENULOOP:
    case WM_EXITMENULOOP:
        return DefWindowProcW(hwnd, msg, wParam, lParam);

    case WM_NOTIFY: {
        if (MarshalNotify(hwnd, wParam, lParam, arm_wndproc,
                          s_instance->mem, executor, marshal_result))
            return marshal_result;
        break; /* ARM pointer — forward directly */
    }
    case WM_NCHITTEST:
    case WM_DISPLAYCHANGE:
        break;
    case WM_DELETEITEM:
    case WM_COMPAREITEM:
        if (lParam > 0 && (lParam >> 32) == 0) break;
        return DefWindowProcW(hwnd, msg, wParam, lParam);

    case WM_WINDOWPOSCHANGING:
    case WM_WINDOWPOSCHANGED:
        if (!lParam) return DefWindowProcW(hwnd, msg, wParam, lParam);
        MarshalWindowPos(hwnd, msg, wParam, lParam, arm_wndproc,
                         s_instance->mem, executor, marshal_result);
        return marshal_result;

    case WM_STYLECHANGING:
    case WM_STYLECHANGED:
        if (!lParam) return DefWindowProcW(hwnd, msg, wParam, lParam);
        MarshalStyleChange(hwnd, msg, wParam, lParam, arm_wndproc,
                           s_instance->mem, executor, marshal_result);
        return marshal_result;

    case WM_SETTEXT:
        if (!lParam) return DefWindowProcW(hwnd, msg, wParam, lParam);
        MarshalSetText(lParam, s_instance->mem, lParam);
        break;

    case WM_GETTEXT:
        if (!lParam || !wParam) return DefWindowProcW(hwnd, msg, wParam, lParam);
        MarshalGetText(hwnd, wParam, lParam, arm_wndproc,
                       s_instance->mem, executor, marshal_result);
        return marshal_result;

    case WM_GETTEXTLENGTH:
        break;

    case WM_CREATE:
    case WM_NCCREATE: {
        /* Populate WinCE style map during WM_NCCREATE (first message to a new window).
           tls_pending_wce_style is set by the CreateWindowExW thunk before calling
           the native ::CreateWindowExW. */
        if (msg == WM_NCCREATE && tls_pending_wce_style) {
            hwnd_wce_style_map[hwnd] = tls_pending_wce_style;
            hwnd_wce_exstyle_map[hwnd] = tls_pending_wce_exstyle;
            /* Clear immediately so child windows created during WM_CREATE
               don't inherit the parent's WCE style via stale TLS value. */
            tls_pending_wce_style = 0;
            tls_pending_wce_exstyle = 0;
        }
        MarshalCreateStruct(lParam, s_instance->mem,
                            s_instance->emu_hinstance, lParam);
        /* Override style/exStyle in the marshaled CREATESTRUCT with original WinCE
           values so ARM code sees the styles it requested, not our WS_POPUP conversion.
           CREATESTRUCT layout: +32 = style, +44 = dwExStyle (matches CS_EMU_ADDR offsets
           in callbacks_marshal.cpp). */
        {
            constexpr uint32_t CS_STYLE_ADDR   = 0x3F000020; /* CS_EMU_ADDR + 32 */
            constexpr uint32_t CS_EXSTYLE_ADDR  = 0x3F00002C; /* CS_EMU_ADDR + 44 */
            auto sit = hwnd_wce_style_map.find(hwnd);
            if (sit != hwnd_wce_style_map.end())
                s_instance->mem.Write32(CS_STYLE_ADDR, sit->second);
            auto eit = hwnd_wce_exstyle_map.find(hwnd);
            if (eit != hwnd_wce_exstyle_map.end())
                s_instance->mem.Write32(CS_EXSTYLE_ADDR, eit->second & 0x0FFFFFFF);
        }
        break;
    }

    case WM_DRAWITEM:
        MarshalDrawItem(lParam, s_instance->mem, lParam);
        break;

    case WM_MEASUREITEM:
        MarshalMeasureItem(lParam, s_instance->mem, lParam);
        break;
    }

    /* WM_SETTINGCHANGE: Desktop sends wParam=SPI, lParam=native string ptr.
       WinCE convention: lParam = SPI constant (for SPI_SETSIPINFO=0xE0). */
    if (msg == WM_SETTINGCHANGE) {
        if (wParam == 0xE0 /* SPI_SETSIPINFO */)
            lParam = 0xE0;
        else
            lParam = 0;
    }

    /* Debug logging for key messages */
    if (msg == WM_PAINT || msg == WM_ERASEBKGND) {
        wchar_t cls[64] = {};
        GetClassNameW(hwnd, cls, 64);
        LOG(API, "[API] EmuWndProc: msg=0x%04X (%s) hwnd=0x%p class='%ls'\n",
            msg, msg == WM_PAINT ? "WM_PAINT" : "WM_ERASEBKGND", hwnd, cls);
    }
    if (msg == WM_CREATE || msg == WM_NCCREATE) {
        wchar_t cls[64] = {};
        GetClassNameW(hwnd, cls, 64);
        LOG(API, "[API] EmuWndProc: msg=0x%04X (%s) hwnd=0x%p class='%ls' arm_wndproc=0x%08X lP=0x%X\n",
            msg, msg == WM_CREATE ? "WM_CREATE" : "WM_NCCREATE", hwnd, cls, arm_wndproc, (uint32_t)lParam);
    }
    if (msg == WM_CLOSE || msg == WM_SYSCOMMAND || msg == WM_DESTROY) {
        wchar_t cls[64] = {};
        GetClassNameW(hwnd, cls, 64);
        LOG(API, "[API] EmuWndProc CLOSE-PATH: msg=0x%04X hwnd=0x%p class='%ls' wP=0x%X lP=0x%X\n",
            msg, hwnd, cls, (uint32_t)wParam, (uint32_t)lParam);
    }
    if (msg == WM_CHAR || msg == WM_KEYDOWN || msg == WM_SETTEXT ||
        msg == WM_LBUTTONDOWN || msg == WM_LBUTTONUP || msg == WM_CAPTURECHANGED ||
        msg == WM_SETFOCUS || msg == WM_KILLFOCUS ||
        msg == WM_INITMENUPOPUP || msg == WM_MENUSELECT) {
        wchar_t cls[64] = {};
        GetClassNameW(hwnd, cls, 64);
        LOG(API, "[API] EmuWndProc: msg=0x%04X hwnd=0x%p class='%ls' wP=0x%X lP=0x%X\n",
            msg, hwnd, cls, (uint32_t)wParam, (uint32_t)lParam);
    }
    if (msg == WM_NOTIFY) {
        wchar_t cls[64] = {};
        GetClassNameW(hwnd, cls, 64);
        int32_t nmCode = 0;
        EmulatedMemory& emem = s_instance->mem;
        uint32_t lp32 = (uint32_t)lParam;
        if (lp32 && emem.IsValid(lp32 + 8))
            nmCode = (int32_t)emem.Read32(lp32 + 8);
        LOG(API, "[API] EmuWndProc WM_NOTIFY: hwnd=0x%p class='%ls' code=%d lP=0x%X\n",
            hwnd, cls, nmCode, lp32);
    }

    uint32_t args[4] = {
        (uint32_t)(uintptr_t)hwnd,
        (uint32_t)msg,
        (uint32_t)wParam,
        (uint32_t)lParam
    };

    uint32_t result = s_instance->callback_executor(arm_wndproc, args, 4);

    if (msg == WM_NOTIFY) {
        LOG(API, "[API] EmuWndProc WM_NOTIFY result=%u (0x%X)\n", result, result);
    }

    /* Copy back results from WM_MEASUREITEM */
    if (msg == WM_MEASUREITEM && native_lParam) {
        MarshalMeasureItemWriteback(native_lParam, s_instance->mem);
    }

    /* Sign-extend the 32-bit result to 64-bit LRESULT. */
    return (LRESULT)(intptr_t)(int32_t)result;
}
