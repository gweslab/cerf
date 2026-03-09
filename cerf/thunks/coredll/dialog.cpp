/* Dialog thunks: CreateDialog, DialogBox, EndDialog, DlgItem functions */
#define NOMINMAX
#include "../win32_thunks.h"
#include "../../log.h"
#include <cstdio>
#include <vector>

/* Helper: compute size of a DLGTEMPLATE (with all items) in emulated memory. */
static uint32_t ComputeDlgTemplateSize(EmulatedMemory& mem, uint32_t addr) {
    uint32_t p = addr;
    uint16_t cdit = mem.Read16(p + 8);
    p += 18;
    uint16_t w = mem.Read16(p);
    if (w == 0x0000) { p += 2; }
    else if (w == 0xFFFF) { p += 4; }
    else { while (mem.Read16(p)) p += 2; p += 2; }
    w = mem.Read16(p);
    if (w == 0x0000) { p += 2; }
    else if (w == 0xFFFF) { p += 4; }
    else { while (mem.Read16(p)) p += 2; p += 2; }
    while (mem.Read16(p)) p += 2; p += 2;
    uint32_t style = mem.Read32(addr);
    if (style & DS_SETFONT) { p += 2; while (mem.Read16(p)) p += 2; p += 2; }
    for (int i = 0; i < cdit; i++) {
        p = (p + 3) & ~3u;
        p += 18;
        w = mem.Read16(p);
        if (w == 0xFFFF) { p += 4; }
        else { while (mem.Read16(p)) p += 2; p += 2; }
        w = mem.Read16(p);
        if (w == 0xFFFF) { p += 4; }
        else { while (mem.Read16(p)) p += 2; p += 2; }
        uint16_t extra = mem.Read16(p);
        p += 2 + extra;
    }
    return p - addr;
}

static std::vector<uint8_t> CopyDlgTemplate(EmulatedMemory& mem, uint32_t addr) {
    uint32_t size = ComputeDlgTemplateSize(mem, addr);
    std::vector<uint8_t> buf(size);
    for (uint32_t i = 0; i < size; i++) buf[i] = mem.Read8(addr + i);
    return buf;
}

/* Strip WinCE-only styles from a copied DLGTEMPLATE buffer.
   Also patches the dialog font: WinCE "System" → configured sysfont (e.g. Tahoma).
   If DS_SETFONT is absent, adds it with the WinCE system font so child controls
   match the WinCE appearance instead of using the desktop "System" bitmap font.
   Returns true if the template had WS_EX_CAPTIONOKBTN in dwExtendedStyle. */
static bool FixupDlgTemplate(std::vector<uint8_t>& tmpl, const std::wstring& sysfont_name) {
    if (tmpl.size() < 10) return false;
    /* DLGTEMPLATE: offset 0 = style (DWORD), offset 4 = dwExtendedStyle (DWORD) */
    uint32_t style   = *(uint32_t*)&tmpl[0];
    uint32_t exStyle = *(uint32_t*)&tmpl[4];
    bool had_captionok = (exStyle & 0x80000000u) != 0;
    exStyle &= ~0x80000000u;   /* strip WS_EX_CAPTIONOKBTN — we render it ourselves */
    *(uint32_t*)&tmpl[4] = exStyle;

    /* Detect DLGTEMPLATEEX vs DLGTEMPLATE.
       DLGTEMPLATEEX has signature 0xFFFF at offset 2, dlgVer=1 at offset 0.
       DLGTEMPLATE:   style(4) exStyle(4) cdit(2) x(2@10) y(2@12) cx(2) cy(2)
       DLGTEMPLATEEX: dlgVer(2) sig(2) helpID(4) exStyle(4) style(4) cdit(2) x(2@18) y(2@20) cx(2) cy(2) */
    bool is_ex = (tmpl.size() >= 4 && *(uint16_t*)&tmpl[2] == 0xFFFF);
    size_t xy_off = is_ex ? 18 : 10;

    /* Clamp dialog position: WinCE uses 16-bit screen coords (max 240x320).
       Values like 0x7FFF (32767) mean "default" on WinCE but produce
       off-screen positioning on desktop Windows. Clamp to 0. */
    if (tmpl.size() >= xy_off + 4) {
        int16_t dlg_x = *(int16_t*)&tmpl[xy_off];
        int16_t dlg_y = *(int16_t*)&tmpl[xy_off + 2];
        if (dlg_x > 500 || dlg_x < 0) *(int16_t*)&tmpl[xy_off] = 0;
        if (dlg_y > 500 || dlg_y < 0) *(int16_t*)&tmpl[xy_off + 2] = 0;
    }

    /* Locate the font field in the template.
       DLGTEMPLATE header: style(4) + exStyle(4) + cdit(2) + x(2) + y(2) + cx(2) + cy(2) = 18 bytes
       Then: menu (sz_Or_Ord), class (sz_Or_Ord), title (sz string), [font if DS_SETFONT] */
    size_t p = 18;
    auto skip_sz_or_ord = [&]() {
        if (p + 2 > tmpl.size()) return;
        uint16_t w = *(uint16_t*)&tmpl[p];
        if (w == 0x0000) { p += 2; }
        else if (w == 0xFFFF) { p += 4; }
        else { while (p + 2 <= tmpl.size() && *(uint16_t*)&tmpl[p]) p += 2; p += 2; }
    };
    skip_sz_or_ord(); /* menu */
    skip_sz_or_ord(); /* class */
    /* title: always a null-terminated wchar string */
    while (p + 2 <= tmpl.size() && *(uint16_t*)&tmpl[p]) p += 2;
    p += 2; /* skip null terminator */

    if (style & DS_SETFONT) {
        /* DS_SETFONT present: pointSize(WORD) then font name (wchar string).
           Keep the original point size — it controls DLU sizing of all controls.
           Only replace the font name so it uses the WinCE system font face.
           IMPORTANT: Each DLGITEMTEMPLATE must be DWORD-aligned, so when the font
           name changes size we must recompute the alignment padding between the
           font name's null terminator and the first item. */
        p += 2; /* skip point size (unchanged) */
        size_t name_start = p;
        while (p + 2 <= tmpl.size() && *(uint16_t*)&tmpl[p]) p += 2;
        p += 2; /* past null */
        /* p = byte after font name null terminator */
        size_t old_items = (p + 3) & ~(size_t)3; /* DWORD-aligned start of items */

        size_t new_name_bytes = (sysfont_name.size() + 1) * 2;
        size_t new_name_end = name_start + new_name_bytes;
        size_t new_items = (new_name_end + 3) & ~(size_t)3;
        size_t new_pad = new_items - new_name_end;

        /* Erase old font name + old alignment padding, insert new name + new padding */
        tmpl.erase(tmpl.begin() + name_start, tmpl.begin() + old_items);
        tmpl.insert(tmpl.begin() + name_start, new_name_bytes + new_pad, 0);
        for (size_t i = 0; i < sysfont_name.size(); i++)
            *(uint16_t*)&tmpl[name_start + i * 2] = (uint16_t)sysfont_name[i];
        *(uint16_t*)&tmpl[name_start + sysfont_name.size() * 2] = 0;
    } else {
        /* No DS_SETFONT: add it with 8pt WinCE system font.
           Must also fix DWORD alignment for items that follow. */
        style |= DS_SETFONT;
        *(uint32_t*)&tmpl[0] = style;
        size_t old_items = (p + 3) & ~(size_t)3; /* current DWORD-aligned item start */

        size_t new_name_bytes = (sysfont_name.size() + 1) * 2;
        size_t font_data_size = 2 + new_name_bytes; /* pointSize + name + null */
        size_t new_font_end = p + font_data_size;
        size_t new_items = (new_font_end + 3) & ~(size_t)3;
        size_t new_pad = new_items - new_font_end;

        /* Erase old alignment padding, insert font data + new padding */
        tmpl.erase(tmpl.begin() + p, tmpl.begin() + old_items);
        tmpl.insert(tmpl.begin() + p, font_data_size + new_pad, 0);
        *(uint16_t*)&tmpl[p] = 8; /* point size */
        for (size_t i = 0; i < sysfont_name.size(); i++)
            *(uint16_t*)&tmpl[p + 2 + i * 2] = (uint16_t)sysfont_name[i];
        *(uint16_t*)&tmpl[p + 2 + sysfont_name.size() * 2] = 0;
    }
    return had_captionok;
}

void Win32Thunks::RegisterDialogHandlers() {
    Thunk("CreateDialogIndirectParamW", 688, [this](uint32_t* regs, EmulatedMemory& mem) -> bool {
        uint32_t hInst = regs[0], lpTemplate = regs[1], hwndParent = regs[2], arm_dlgProc = regs[3];
        LPARAM initParam = (LPARAM)ReadStackArg(regs, mem, 0);
        auto tmpl = CopyDlgTemplate(mem, lpTemplate);
        bool has_captionok = FixupDlgTemplate(tmpl, wce_sysfont_name);
        /* Use the ARM module's native resource handle so SS_ICON/SS_BITMAP
           controls in the dialog template find their resources correctly. */
        HMODULE native_mod = GetNativeModuleForResources(hInst);
        HINSTANCE dlg_inst = native_mod ? (HINSTANCE)native_mod : GetModuleHandleW(NULL);
        /* Pre-register the ARM dlgproc so EmuDlgProc can dispatch WM_INITDIALOG
           which is sent during CreateDialogIndirectParamW before it returns. */
        pending_arm_dlgproc = arm_dlgProc;
        HWND dlg = CreateDialogIndirectParamW(dlg_inst,
            (LPCDLGTEMPLATEW)tmpl.data(), (HWND)(intptr_t)(int32_t)hwndParent, EmuDlgProc, initParam);
        pending_arm_dlgproc = 0;
        LOG(API, "[API] CreateDialogIndirectParamW(parent=0x%X, dlgproc=0x%08X) -> HWND=0x%p (err=%lu)\n",
            hwndParent, arm_dlgProc, dlg, dlg ? 0UL : GetLastError());
        /* Only set the DlgProc if it wasn't already updated during WM_INITDIALOG
           (MFC's DialogFunc sets DWL_DLGPROC to the real handler during init) */
        if (dlg && arm_dlgProc && hwnd_dlgproc_map.find(dlg) == hwnd_dlgproc_map.end())
            hwnd_dlgproc_map[dlg] = arm_dlgProc;
        if (dlg) {
            /* Apply theme BEFORE CaptionOk so OK button paints on top (LIFO) */
            ApplyWindowTheme(dlg, true);
            EnumChildWindows(dlg, [](HWND child, LPARAM lp) -> BOOL {
                ((Win32Thunks*)lp)->ApplyWindowTheme(child, false);
                return TRUE;
            }, (LPARAM)this);
            if (has_captionok) {
                captionok_hwnds.insert(dlg);
                InstallCaptionOk(dlg);
                LOG(API, "[API]   Dialog HWND=0x%p has WS_EX_CAPTIONOKBTN\n", dlg);
            }
        }
        regs[0] = (uint32_t)(uintptr_t)dlg;
        return true;
    });
    Thunk("DialogBoxIndirectParamW", 690, [this](uint32_t* regs, EmulatedMemory& mem) -> bool {
        uint32_t hInst = regs[0], lpTemplate = regs[1], hwndParent = regs[2], arm_dlgProc = regs[3];
        LPARAM initParam = (LPARAM)ReadStackArg(regs, mem, 0);
        HWND parent = (HWND)(intptr_t)(int32_t)hwndParent;
        auto tmpl = CopyDlgTemplate(mem, lpTemplate);
        bool has_captionok = FixupDlgTemplate(tmpl, wce_sysfont_name);
        HMODULE native_mod = GetNativeModuleForResources(hInst);
        HINSTANCE dlg_inst = native_mod ? (HINSTANCE)native_mod : GetModuleHandleW(NULL);
        modal_dlg_ended = false;
        modal_dlg_result = 0;
        HWND dlg = CreateDialogIndirectParamW(dlg_inst,
            (LPCDLGTEMPLATEW)tmpl.data(), parent, EmuDlgProc, initParam);
        if (dlg && arm_dlgProc) {
            hwnd_dlgproc_map[dlg] = arm_dlgProc;
            /* Apply theme BEFORE CaptionOk so OK button paints on top (LIFO) */
            ApplyWindowTheme(dlg, true);
            EnumChildWindows(dlg, [](HWND child, LPARAM lp) -> BOOL {
                ((Win32Thunks*)lp)->ApplyWindowTheme(child, false);
                return TRUE;
            }, (LPARAM)this);
            if (has_captionok) {
                captionok_hwnds.insert(dlg);
                InstallCaptionOk(dlg);
                LOG(API, "[API]   Modal dialog HWND=0x%p has WS_EX_CAPTIONOKBTN\n", dlg);
            }
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
        BOOL ret = MapDialogRect(hwnd, &rc);
        mem.Write32(rect_addr + 0,  (uint32_t)rc.left);
        mem.Write32(rect_addr + 4,  (uint32_t)rc.top);
        mem.Write32(rect_addr + 8,  (uint32_t)rc.right);
        mem.Write32(rect_addr + 12, (uint32_t)rc.bottom);
        regs[0] = ret;
        return true;
    });
}
