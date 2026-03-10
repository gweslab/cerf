/* Dialog thunks: CreateDialog, DialogBox, EndDialog, DlgItem functions */
#define NOMINMAX
#include "../win32_thunks.h"
#include "dialog_template.h"
#include "../../log.h"
#include <cstdio>
#include <vector>

void Win32Thunks::RegisterDialogHandlers() {
    Thunk("CreateDialogIndirectParamW", 688, [this](uint32_t* regs, EmulatedMemory& mem) -> bool {
        uint32_t hInst = regs[0], lpTemplate = regs[1], hwndParent = regs[2], arm_dlgProc = regs[3];
        LPARAM initParam = (LPARAM)ReadStackArg(regs, mem, 0);
        auto tmpl = CopyDlgTemplate(mem, lpTemplate);
        auto fixup = FixupDlgTemplate(tmpl, wce_sysfont_name);
        LOG(API, "[API] CreateDialogIndirectParamW: template wce_style=0x%08X\n", fixup.wce_style);
        HMODULE native_mod = GetNativeModuleForResources(hInst);
        HINSTANCE dlg_inst = native_mod ? (HINSTANCE)native_mod : GetModuleHandleW(NULL);
        pending_arm_dlgproc = arm_dlgProc;
        HWND dlg = CreateDialogIndirectParamW(dlg_inst,
            (LPCDLGTEMPLATEW)tmpl.data(), (HWND)(intptr_t)(int32_t)hwndParent, EmuDlgProc, initParam);
        pending_arm_dlgproc = 0;
        LOG(API, "[API] CreateDialogIndirectParamW(parent=0x%X, dlgproc=0x%08X) -> HWND=0x%p (err=%lu)\n",
            hwndParent, arm_dlgProc, dlg, dlg ? 0UL : GetLastError());
        if (dlg && arm_dlgProc && hwnd_dlgproc_map.find(dlg) == hwnd_dlgproc_map.end())
            hwnd_dlgproc_map[dlg] = arm_dlgProc;
        if (dlg) {
            if (!fixup.is_child) {
                /* Non-child dialog: add to WinCE style maps so WM_NCCALCSIZE and
                   PaintWinCENCArea draw the WinCE NC area (border + caption + OK). */
                hwnd_wce_style_map[dlg] = fixup.wce_style;
                hwnd_wce_exstyle_map[dlg] = fixup.wce_exstyle;
                ApplyWindowTheme(dlg, true);
                if (fixup.had_captionok) {
                    captionok_hwnds.insert(dlg);
                    LOG(API, "[API]   Dialog HWND=0x%p has WS_EX_CAPTIONOKBTN\n", dlg);
                }
                /* Expand window to account for WinCE NC area.  The native dialog
                   manager sized the window for WS_POPUP (no frame), but our
                   WM_NCCALCSIZE handler carves out border + caption.  Without
                   expansion the client area shrinks and controls get clipped.
                   SWP_FRAMECHANGED also triggers WM_NCCALCSIZE + WM_NCPAINT so
                   the caption bar and buttons appear immediately. */
                bool dlg_cap = (fixup.wce_style & WS_CAPTION) == WS_CAPTION;
                bool dlg_brd = (fixup.wce_style & WS_BORDER) != 0;
                if (dlg_cap || dlg_brd) {
                    RECT wr;
                    GetWindowRect(dlg, &wr);
                    int brd = 1;
                    int cap = dlg_cap ? GetSystemMetrics(SM_CYCAPTION) : 0;
                    SetWindowPos(dlg, NULL, 0, 0,
                        (wr.right - wr.left) + 2 * brd,
                        (wr.bottom - wr.top) + 2 * brd + cap,
                        SWP_NOMOVE | SWP_NOZORDER | SWP_NOACTIVATE | SWP_FRAMECHANGED);
                }
            } else {
                /* Child dialog (e.g. property page): theme background only,
                   no NC area or style map — it lives inside its parent. */
                ApplyWindowTheme(dlg, false);
            }
            EnumChildWindows(dlg, [](HWND child, LPARAM lp) -> BOOL {
                wchar_t cls[64] = {};
                GetClassNameW(child, cls, 64);
                LOG(API, "[API]   EnumChild: %p class='%ls'\n", child, cls);
                ((Win32Thunks*)lp)->ApplyWindowTheme(child, false);
                return TRUE;
            }, (LPARAM)this);
        }
        regs[0] = (uint32_t)(uintptr_t)dlg;
        return true;
    });
    Thunk("DialogBoxIndirectParamW", 690, [this](uint32_t* regs, EmulatedMemory& mem) -> bool {
        uint32_t hInst = regs[0], lpTemplate = regs[1], hwndParent = regs[2], arm_dlgProc = regs[3];
        LPARAM initParam = (LPARAM)ReadStackArg(regs, mem, 0);
        HWND parent = (HWND)(intptr_t)(int32_t)hwndParent;
        auto tmpl = CopyDlgTemplate(mem, lpTemplate);
        auto fixup = FixupDlgTemplate(tmpl, wce_sysfont_name);
        HMODULE native_mod = GetNativeModuleForResources(hInst);
        HINSTANCE dlg_inst = native_mod ? (HINSTANCE)native_mod : GetModuleHandleW(NULL);
        modal_dlg_ended = false;
        modal_dlg_result = 0;
        HWND dlg = CreateDialogIndirectParamW(dlg_inst,
            (LPCDLGTEMPLATEW)tmpl.data(), parent, EmuDlgProc, initParam);
        if (dlg && arm_dlgProc) {
            hwnd_dlgproc_map[dlg] = arm_dlgProc;
            if (!fixup.is_child) {
                hwnd_wce_style_map[dlg] = fixup.wce_style;
                hwnd_wce_exstyle_map[dlg] = fixup.wce_exstyle;
                ApplyWindowTheme(dlg, true);
                if (fixup.had_captionok) {
                    captionok_hwnds.insert(dlg);
                    LOG(API, "[API]   Modal dialog HWND=0x%p has WS_EX_CAPTIONOKBTN\n", dlg);
                }
                /* Expand window for WinCE NC area (same as modeless path above) */
                bool dlg_cap = (fixup.wce_style & WS_CAPTION) == WS_CAPTION;
                bool dlg_brd = (fixup.wce_style & WS_BORDER) != 0;
                if (dlg_cap || dlg_brd) {
                    RECT wr;
                    GetWindowRect(dlg, &wr);
                    int brd = 1;
                    int cap = dlg_cap ? GetSystemMetrics(SM_CYCAPTION) : 0;
                    SetWindowPos(dlg, NULL, 0, 0,
                        (wr.right - wr.left) + 2 * brd,
                        (wr.bottom - wr.top) + 2 * brd + cap,
                        SWP_NOMOVE | SWP_NOZORDER | SWP_NOACTIVATE | SWP_FRAMECHANGED);
                }
            } else {
                ApplyWindowTheme(dlg, false);
            }
            EnumChildWindows(dlg, [](HWND child, LPARAM lp) -> BOOL {
                ((Win32Thunks*)lp)->ApplyWindowTheme(child, false);
                return TRUE;
            }, (LPARAM)this);
            uint32_t args[4] = { (uint32_t)(uintptr_t)dlg, WM_INITDIALOG, 0, (uint32_t)initParam };
            callback_executor(arm_dlgProc, args, 4);
        }
        if (dlg) {
            ShowWindow(dlg, SW_SHOW);
            if (parent) EnableWindow(parent, FALSE);
            MSG msg;
            while (!modal_dlg_ended && GetMessageW(&msg, NULL, 0, 0)) {
                if (!IsDialogMessageW(dlg, &msg)) { TranslateMessage(&msg); DispatchMessageW(&msg); }
            }
            if (parent) EnableWindow(parent, TRUE);
            if (captionok_hwnds.erase(dlg)) RemoveCaptionOk(dlg);
            hwnd_dlgproc_map.erase(dlg);
            DestroyWindow(dlg);
            if (parent) SetForegroundWindow(parent);
        }
        regs[0] = (uint32_t)modal_dlg_result;
        return true;
    });
    Thunk("EndDialog", 691, [](uint32_t* regs, EmulatedMemory&) -> bool {
        HWND dlg = (HWND)(intptr_t)(int32_t)regs[0];
        modal_dlg_result = (INT_PTR)(int32_t)regs[1];
        modal_dlg_ended = true;
        ShowWindow(dlg, SW_HIDE);
        LOG(API, "[API] EndDialog(hwnd=0x%p, result=%d)\n", dlg, (int)modal_dlg_result);
        regs[0] = 1;
        return true;
    });
    Thunk("GetDlgItem", 692, [](uint32_t* regs, EmulatedMemory&) -> bool {
        regs[0] = (uint32_t)(uintptr_t)GetDlgItem((HWND)(intptr_t)(int32_t)regs[0], regs[1]);
        return true;
    });
    Thunk("SetDlgItemTextW", 686, [this](uint32_t* regs, EmulatedMemory& mem) -> bool {
        std::wstring text = ReadWStringFromEmu(mem, regs[2]);
        regs[0] = SetDlgItemTextW((HWND)(intptr_t)(int32_t)regs[0], regs[1], text.c_str());
        return true;
    });
    Thunk("GetDlgItemTextW", 687, [this](uint32_t* regs, EmulatedMemory& mem) -> bool {
        wchar_t buf[1024] = {}; uint32_t maxlen = regs[3]; if (maxlen > 1024) maxlen = 1024;
        int ret = GetDlgItemTextW((HWND)(intptr_t)(int32_t)regs[0], regs[1], buf, maxlen);
        for (int i = 0; i <= ret; i++) mem.Write16(regs[2] + i * 2, buf[i]);
        regs[0] = ret;
        return true;
    });
    Thunk("SendDlgItemMessageW", 685, [this](uint32_t* regs, EmulatedMemory& mem) -> bool {
        regs[0] = (uint32_t)SendDlgItemMessageW((HWND)(intptr_t)(int32_t)regs[0], regs[1], regs[2], regs[3], ReadStackArg(regs, mem, 0));
        return true;
    });
    Thunk("CheckRadioButton", 684, [](uint32_t* regs, EmulatedMemory&) -> bool {
        regs[0] = CheckRadioButton((HWND)(intptr_t)(int32_t)regs[0], regs[1], regs[2], regs[3]);
        return true;
    });
    Thunk("DefDlgProcW", 689, [](uint32_t* regs, EmulatedMemory&) -> bool {
        regs[0] = (uint32_t)DefDlgProcW((HWND)(intptr_t)(int32_t)regs[0], regs[1], regs[2], regs[3]);
        return true;
    });
    Thunk("GetDlgCtrlID", 693, [](uint32_t* regs, EmulatedMemory&) -> bool {
        regs[0] = GetDlgCtrlID((HWND)(intptr_t)(int32_t)regs[0]);
        return true;
    });
    Thunk("GetNextDlgTabItem", 696, [](uint32_t* regs, EmulatedMemory&) -> bool {
        regs[0] = (uint32_t)(uintptr_t)GetNextDlgTabItem(
            (HWND)(intptr_t)(int32_t)regs[0], (HWND)(intptr_t)(int32_t)regs[1], regs[2]);
        return true;
    });
    Thunk("IsDialogMessageW", 698, [](uint32_t* regs, EmulatedMemory&) -> bool {
        regs[0] = 0; return true;
    });
    Thunk("MapDialogRect", 699, [](uint32_t* regs, EmulatedMemory& mem) -> bool {
        HWND hwnd = (HWND)(intptr_t)(int32_t)regs[0];
        uint32_t rect_addr = regs[1];
        RECT rc;
        rc.left   = (int32_t)mem.Read32(rect_addr + 0);
        rc.top    = (int32_t)mem.Read32(rect_addr + 4);
        rc.right  = (int32_t)mem.Read32(rect_addr + 8);
        rc.bottom = (int32_t)mem.Read32(rect_addr + 12);
        RECT dlu = rc; /* save DLU values for logging */
        BOOL ret = MapDialogRect(hwnd, &rc);
        LOG(API, "[API] MapDialogRect(hwnd=%p) DLU{%ld,%ld,%ld,%ld} -> PX{%ld,%ld,%ld,%ld}\n",
            hwnd, dlu.left, dlu.top, dlu.right, dlu.bottom, rc.left, rc.top, rc.right, rc.bottom);
        mem.Write32(rect_addr + 0,  (uint32_t)rc.left);
        mem.Write32(rect_addr + 4,  (uint32_t)rc.top);
        mem.Write32(rect_addr + 8,  (uint32_t)rc.right);
        mem.Write32(rect_addr + 12, (uint32_t)rc.bottom);
        regs[0] = ret;
        return true;
    });
}
