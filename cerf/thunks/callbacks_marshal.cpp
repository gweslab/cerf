#define NOMINMAX
#define _CRT_SECURE_NO_WARNINGS
#include "callbacks_marshal.h"
#include "../log.h"
#include <commctrl.h>

/* Emulated memory addresses for marshaling buffers */
static constexpr uint32_t NM_EMU_BASE  = 0x3F003000;
static constexpr uint32_t WP_EMU_ADDR  = 0x3F002100;
static constexpr uint32_t SS_EMU_ADDR  = 0x3F002200;
static constexpr uint32_t ST_EMU_ADDR  = 0x3F002400;
static constexpr uint32_t GT_EMU_ADDR  = 0x3F002800;
static constexpr uint32_t CS_EMU_ADDR  = 0x3F000000;
static constexpr uint32_t WDI_EMU_ADDR = 0x3F002000;
static constexpr uint32_t WMI_EMU_ADDR = 0x3F002500;

static void EnsureAlloc(EmulatedMemory& emem, uint32_t addr, uint32_t size) {
    if (!emem.IsValid(addr)) emem.Alloc(addr, size);
}

bool MarshalNotify(HWND hwnd, WPARAM wParam, LPARAM lParam,
                   uint32_t arm_wndproc, EmulatedMemory& emem,
                   MarshalCallbackExecutor executor, LRESULT& out_result)
{
    /* ARM-originated WM_NOTIFY: lParam fits in 32 bits */
    if (lParam > 0 && (lParam >> 32) == 0) {
        uint32_t arm_lp = (uint32_t)lParam;
        int32_t code_peek = (int32_t)emem.Read32(arm_lp + 8);
        if (code_peek == LVN_GETDISPINFOW || code_peek == LVN_GETDISPINFOA) {
            uint32_t mask = emem.Read32(arm_lp + 12);
            int iItem = (int)emem.Read32(arm_lp + 16);
            int iImage = (int)emem.Read32(arm_lp + 40);
            uint32_t pszText = emem.Read32(arm_lp + 32);
            LOG(API, "[DISP] LVN_GETDISPINFO(ARM) BEFORE: iItem=%d mask=0x%X iImage=%d pszText=0x%08X\n",
                iItem, mask, iImage, pszText);
            uint32_t args[4] = {
                (uint32_t)(uintptr_t)hwnd, WM_NOTIFY,
                (uint32_t)wParam, arm_lp
            };
            uint32_t result = executor(arm_wndproc, args, 4);
            iImage = (int)emem.Read32(arm_lp + 40);
            pszText = emem.Read32(arm_lp + 32);
            std::wstring disp_text;
            if (pszText && (mask & 0x0001 /*LVIF_TEXT*/)) {
                for (int i = 0; i < 64; i++) {
                    wchar_t c = (wchar_t)emem.Read16(pszText + i * 2);
                    if (!c) break;
                    disp_text += c;
                }
            }
            LOG(API, "[DISP] LVN_GETDISPINFO(ARM) AFTER: iItem=%d iImage=%d text='%ls'\n",
                iItem, iImage, disp_text.c_str());
            out_result = (LRESULT)(intptr_t)(int32_t)result;
            return true;
        }
        return false; /* ARM pointer, not LVN_GETDISPINFO — forward directly */
    }

    if (!lParam) {
        out_result = DefWindowProcW(hwnd, WM_NOTIFY, wParam, lParam);
        return true;
    }

    /* Native NMHDR at lParam. Marshal to ARM emulated memory. */
    NMHDR* pnm = (NMHDR*)lParam;
    EnsureAlloc(emem, NM_EMU_BASE, 0x1000);
    int code = pnm->code;

    if (code == LVN_GETDISPINFOW || code == LVN_GETDISPINFOA) {
        NMLVDISPINFOW* pdi = (NMLVDISPINFOW*)lParam;
        uint32_t a = NM_EMU_BASE;
        /* NMHDR */
        emem.Write32(a + 0, (uint32_t)(uintptr_t)pdi->hdr.hwndFrom);
        emem.Write32(a + 4, (uint32_t)pdi->hdr.idFrom);
        emem.Write32(a + 8, (uint32_t)pdi->hdr.code);
        /* ARM LVITEMW at offset 12 */
        emem.Write32(a + 12, pdi->item.mask);
        emem.Write32(a + 16, pdi->item.iItem);
        emem.Write32(a + 20, pdi->item.iSubItem);
        emem.Write32(a + 24, pdi->item.state);
        emem.Write32(a + 28, pdi->item.stateMask);
        uint32_t text_buf_emu = NM_EMU_BASE + 0x100;
        int text_max = pdi->item.cchTextMax > 0 ? pdi->item.cchTextMax : 260;
        if (text_max > 400) text_max = 400;
        emem.Write32(a + 32, text_buf_emu);
        emem.Write32(a + 36, text_max);
        emem.Write32(a + 40, pdi->item.iImage);
        emem.Write32(a + 44, (uint32_t)(int32_t)pdi->item.lParam);
        emem.Write16(text_buf_emu, 0);
        uint32_t args[4] = {
            (uint32_t)(uintptr_t)hwnd, WM_NOTIFY,
            (uint32_t)wParam, a
        };
        uint32_t result = executor(arm_wndproc, args, 4);
        pdi->item.state = emem.Read32(a + 24);
        pdi->item.iImage = (int)emem.Read32(a + 40);
        pdi->item.lParam = (LPARAM)(int32_t)emem.Read32(a + 44);
        if (pdi->item.mask & LVIF_TEXT) {
            uint32_t arm_text_ptr = emem.Read32(a + 32);
            if (arm_text_ptr && pdi->item.pszText && pdi->item.cchTextMax > 0) {
                int i;
                for (i = 0; i < pdi->item.cchTextMax - 1; i++) {
                    wchar_t c = (wchar_t)emem.Read16(arm_text_ptr + i * 2);
                    pdi->item.pszText[i] = c;
                    if (!c) break;
                }
                pdi->item.pszText[i] = 0;
            }
        }
        out_result = (LRESULT)(intptr_t)(int32_t)result;
        return true;
    }

    /* Other native WM_NOTIFY codes: marshal basic NMHDR + extra data */
    {
        uint32_t a = NM_EMU_BASE;
        emem.Write32(a + 0, (uint32_t)(uintptr_t)pnm->hwndFrom);
        emem.Write32(a + 4, (uint32_t)pnm->idFrom);
        emem.Write32(a + 8, (uint32_t)pnm->code);
        uint8_t* src = (uint8_t*)pnm + 12;
        for (int i = 0; i < 128; i++)
            emem.Write8(a + 12 + i, src[i]);
        uint32_t args[4] = {
            (uint32_t)(uintptr_t)hwnd, WM_NOTIFY,
            (uint32_t)wParam, a
        };
        uint32_t result = executor(arm_wndproc, args, 4);
        out_result = (LRESULT)(intptr_t)(int32_t)result;
        return true;
    }
}

void MarshalWindowPos(HWND hwnd, UINT msg, WPARAM wParam, LPARAM lParam,
                      uint32_t arm_wndproc, EmulatedMemory& emem,
                      MarshalCallbackExecutor executor, LRESULT& out_result)
{
    WINDOWPOS* wp = (WINDOWPOS*)lParam;
    {
        wchar_t cls[64] = {};
        GetClassNameW(hwnd, cls, 64);
        LOG(API, "[API] EmuWndProc %s: hwnd=0x%p class='%ls' x=%d y=%d cx=%d cy=%d flags=0x%X\n",
            msg == WM_WINDOWPOSCHANGED ? "WM_WINDOWPOSCHANGED" : "WM_WINDOWPOSCHANGING",
            hwnd, cls, wp->x, wp->y, wp->cx, wp->cy, wp->flags);
    }
    EnsureAlloc(emem, WP_EMU_ADDR, 0x1000);
    emem.Write32(WP_EMU_ADDR + 0,  (uint32_t)(uintptr_t)wp->hwnd);
    emem.Write32(WP_EMU_ADDR + 4,  (uint32_t)(uintptr_t)wp->hwndInsertAfter);
    emem.Write32(WP_EMU_ADDR + 8,  wp->x);
    emem.Write32(WP_EMU_ADDR + 12, wp->y);
    emem.Write32(WP_EMU_ADDR + 16, wp->cx);
    emem.Write32(WP_EMU_ADDR + 20, wp->cy);
    emem.Write32(WP_EMU_ADDR + 24, wp->flags);
    uint32_t args[4] = {
        (uint32_t)(uintptr_t)hwnd, (uint32_t)msg,
        (uint32_t)wParam, (uint32_t)WP_EMU_ADDR
    };
    uint32_t result = executor(arm_wndproc, args, 4);
    if (msg == WM_WINDOWPOSCHANGING) {
        wp->x     = (int)emem.Read32(WP_EMU_ADDR + 8);
        wp->y     = (int)emem.Read32(WP_EMU_ADDR + 12);
        wp->cx    = (int)emem.Read32(WP_EMU_ADDR + 16);
        wp->cy    = (int)emem.Read32(WP_EMU_ADDR + 20);
        wp->flags = emem.Read32(WP_EMU_ADDR + 24);
    }
    out_result = (LRESULT)(intptr_t)(int32_t)result;
}

void MarshalStyleChange(HWND hwnd, UINT msg, WPARAM wParam, LPARAM lParam,
                        uint32_t arm_wndproc, EmulatedMemory& emem,
                        MarshalCallbackExecutor executor, LRESULT& out_result)
{
    STYLESTRUCT* ss = (STYLESTRUCT*)lParam;
    EnsureAlloc(emem, SS_EMU_ADDR, 0x1000);
    emem.Write32(SS_EMU_ADDR + 0, ss->styleOld);
    emem.Write32(SS_EMU_ADDR + 4, ss->styleNew);
    uint32_t args[4] = {
        (uint32_t)(uintptr_t)hwnd, (uint32_t)msg,
        (uint32_t)wParam, (uint32_t)SS_EMU_ADDR
    };
    uint32_t result = executor(arm_wndproc, args, 4);
    if (msg == WM_STYLECHANGING)
        ss->styleNew = emem.Read32(SS_EMU_ADDR + 4);
    out_result = (LRESULT)(intptr_t)(int32_t)result;
}

void MarshalSetText(LPARAM lParam, EmulatedMemory& emem, LPARAM& out_lParam)
{
    const wchar_t* text = (const wchar_t*)lParam;
    size_t len = wcslen(text);
    uint32_t need = (uint32_t)((len + 1) * 2);
    if (need > 0x1000) need = 0x1000;
    EnsureAlloc(emem, ST_EMU_ADDR, 0x1000);
    uint32_t copyLen = (need / 2) - 1;
    for (uint32_t i = 0; i < copyLen; i++)
        emem.Write16(ST_EMU_ADDR + i * 2, text[i]);
    emem.Write16(ST_EMU_ADDR + copyLen * 2, 0);
    out_lParam = (LPARAM)ST_EMU_ADDR;
}

void MarshalGetText(HWND hwnd, WPARAM wParam, LPARAM lParam,
                    uint32_t arm_wndproc, EmulatedMemory& emem,
                    MarshalCallbackExecutor executor, LRESULT& out_result)
{
    EnsureAlloc(emem, GT_EMU_ADDR, 0x1000);
    uint32_t maxChars = (uint32_t)wParam;
    if (maxChars > 2000) maxChars = 2000;
    emem.Write16(GT_EMU_ADDR, 0);
    uint32_t args[4] = {
        (uint32_t)(uintptr_t)hwnd, (uint32_t)WM_GETTEXT,
        maxChars, (uint32_t)GT_EMU_ADDR
    };
    uint32_t result = executor(arm_wndproc, args, 4);
    wchar_t* native_buf = (wchar_t*)lParam;
    for (uint32_t i = 0; i < maxChars; i++) {
        native_buf[i] = (wchar_t)emem.Read16(GT_EMU_ADDR + i * 2);
        if (native_buf[i] == 0) break;
    }
    native_buf[maxChars - 1] = 0;
    out_result = (LRESULT)(intptr_t)(int32_t)result;
}

void MarshalCreateStruct(LPARAM lParam, EmulatedMemory& emem,
                         uint32_t emu_hinstance, LPARAM& out_lParam)
{
    CREATESTRUCTW* cs = (CREATESTRUCTW*)lParam;
    EnsureAlloc(emem, CS_EMU_ADDR, 0x1000);
    /* Marshal lpszName string at CS_EMU_ADDR + 0x100 */
    uint32_t name_ptr = 0;
    if (cs->lpszName && !IS_INTRESOURCE(cs->lpszName)) {
        name_ptr = CS_EMU_ADDR + 0x100;
        const wchar_t* name = cs->lpszName;
        uint32_t off = 0;
        for (; name[off] && off < 200; off++)
            emem.Write16(name_ptr + off * 2, name[off]);
        emem.Write16(name_ptr + off * 2, 0);
    }
    /* Marshal lpszClass string at CS_EMU_ADDR + 0x300 */
    uint32_t class_ptr = 0;
    if (cs->lpszClass && !IS_INTRESOURCE(cs->lpszClass)) {
        class_ptr = CS_EMU_ADDR + 0x300;
        const wchar_t* cls = cs->lpszClass;
        uint32_t off = 0;
        for (; cls[off] && off < 200; off++)
            emem.Write16(class_ptr + off * 2, cls[off]);
        emem.Write16(class_ptr + off * 2, 0);
    }
    emem.Write32(CS_EMU_ADDR + 0,  (uint32_t)(uintptr_t)cs->lpCreateParams);
    emem.Write32(CS_EMU_ADDR + 4,  emu_hinstance);
    emem.Write32(CS_EMU_ADDR + 8,  0);
    emem.Write32(CS_EMU_ADDR + 12, (uint32_t)(uintptr_t)cs->hwndParent);
    emem.Write32(CS_EMU_ADDR + 16, cs->cy);
    emem.Write32(CS_EMU_ADDR + 20, cs->cx);
    emem.Write32(CS_EMU_ADDR + 24, cs->y);
    emem.Write32(CS_EMU_ADDR + 28, cs->x);
    emem.Write32(CS_EMU_ADDR + 32, cs->style);
    emem.Write32(CS_EMU_ADDR + 36, name_ptr);
    emem.Write32(CS_EMU_ADDR + 40, class_ptr);
    emem.Write32(CS_EMU_ADDR + 44, cs->dwExStyle);
    out_lParam = (LPARAM)CS_EMU_ADDR;
}

void MarshalDrawItem(LPARAM lParam, EmulatedMemory& emem, LPARAM& out_lParam)
{
    EnsureAlloc(emem, WDI_EMU_ADDR, 0x1000);
    DRAWITEMSTRUCT* dis = (DRAWITEMSTRUCT*)lParam;
    emem.Write32(WDI_EMU_ADDR + 0,  dis->CtlType);
    emem.Write32(WDI_EMU_ADDR + 4,  dis->CtlID);
    emem.Write32(WDI_EMU_ADDR + 8,  dis->itemID);
    emem.Write32(WDI_EMU_ADDR + 12, dis->itemAction);
    emem.Write32(WDI_EMU_ADDR + 16, dis->itemState);
    emem.Write32(WDI_EMU_ADDR + 20, (uint32_t)(uintptr_t)dis->hwndItem);
    emem.Write32(WDI_EMU_ADDR + 24, (uint32_t)(uintptr_t)dis->hDC);
    emem.Write32(WDI_EMU_ADDR + 28, dis->rcItem.left);
    emem.Write32(WDI_EMU_ADDR + 32, dis->rcItem.top);
    emem.Write32(WDI_EMU_ADDR + 36, dis->rcItem.right);
    emem.Write32(WDI_EMU_ADDR + 40, dis->rcItem.bottom);
    emem.Write32(WDI_EMU_ADDR + 44, (uint32_t)dis->itemData);
    out_lParam = (LPARAM)WDI_EMU_ADDR;
}

void MarshalMeasureItem(LPARAM lParam, EmulatedMemory& emem, LPARAM& out_lParam)
{
    EnsureAlloc(emem, WMI_EMU_ADDR, 0x1000);
    MEASUREITEMSTRUCT* mis = (MEASUREITEMSTRUCT*)lParam;
    emem.Write32(WMI_EMU_ADDR + 0,  mis->CtlType);
    emem.Write32(WMI_EMU_ADDR + 4,  mis->CtlID);
    emem.Write32(WMI_EMU_ADDR + 8,  mis->itemID);
    emem.Write32(WMI_EMU_ADDR + 12, mis->itemWidth);
    emem.Write32(WMI_EMU_ADDR + 16, mis->itemHeight);
    emem.Write32(WMI_EMU_ADDR + 20, (uint32_t)mis->itemData);
    out_lParam = (LPARAM)WMI_EMU_ADDR;
}

void MarshalMeasureItemWriteback(LPARAM native_lParam, EmulatedMemory& emem)
{
    MEASUREITEMSTRUCT* mis = (MEASUREITEMSTRUCT*)native_lParam;
    mis->itemWidth  = emem.Read32(WMI_EMU_ADDR + 12);
    mis->itemHeight = emem.Read32(WMI_EMU_ADDR + 16);
}
