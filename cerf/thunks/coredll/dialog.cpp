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
static bool FixupDlgTemplate(std::vector<uint8_t>& tmpl, const std::wstring& sysfont_name, LONG sysfont_height) {
    if (tmpl.size() < 10) return false;
    /* DLGTEMPLATE: offset 0 = style (DWORD), offset 4 = dwExtendedStyle (DWORD) */
    uint32_t style   = *(uint32_t*)&tmpl[0];
    uint32_t exStyle = *(uint32_t*)&tmpl[4];
    bool had_captionok = (exStyle & 0x80000000u) != 0;
    exStyle &= ~0x80000000u;   /* strip WS_EX_CAPTIONOKBTN — we render it ourselves */
    *(uint32_t*)&tmpl[4] = exStyle;

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
        /* DS_SETFONT present: pointSize(WORD) then font name (wchar string) */
        size_t font_offset = p;
        /* Compute point size from lfHeight: abs(height) if negative */
        int16_t point_size = (int16_t)(sysfont_height < 0 ? -sysfont_height : sysfont_height);
        *(uint16_t*)&tmpl[font_offset] = (uint16_t)point_size;
        p += 2; /* skip point size */
        /* Replace font name with sysfont */
        size_t name_start = p;
        while (p + 2 <= tmpl.size() && *(uint16_t*)&tmpl[p]) p += 2;
        p += 2; /* past null */
        size_t old_name_bytes = p - name_start;
        size_t new_name_bytes = (sysfont_name.size() + 1) * 2;
        if (old_name_bytes != new_name_bytes) {
            /* Resize: shift everything after the font name */
            int diff = (int)new_name_bytes - (int)old_name_bytes;
            if (diff > 0) tmpl.insert(tmpl.begin() + name_start, diff, 0);
            else if (diff < 0) tmpl.erase(tmpl.begin() + name_start, tmpl.begin() + name_start - diff);
        }
        for (size_t i = 0; i < sysfont_name.size(); i++)
            *(uint16_t*)&tmpl[name_start + i * 2] = (uint16_t)sysfont_name[i];
        *(uint16_t*)&tmpl[name_start + sysfont_name.size() * 2] = 0;
    } else {
        /* No DS_SETFONT: add it. Insert pointSize + font name at position p. */
        style |= DS_SETFONT;
        *(uint32_t*)&tmpl[0] = style;
        int16_t point_size = (int16_t)(sysfont_height < 0 ? -sysfont_height : sysfont_height);
        size_t insert_bytes = 2 + (sysfont_name.size() + 1) * 2;
        tmpl.insert(tmpl.begin() + p, insert_bytes, 0);
        *(uint16_t*)&tmpl[p] = (uint16_t)point_size;
        for (size_t i = 0; i < sysfont_name.size(); i++)
            *(uint16_t*)&tmpl[p + 2 + i * 2] = (uint16_t)sysfont_name[i];
        *(uint16_t*)&tmpl[p + 2 + sysfont_name.size() * 2] = 0;
    }
    return had_captionok;
}

void Win32Thunks::RegisterDialogHandlers() {
    Thunk("CreateDialogIndirectParamW", 688, [this](uint32_t* regs, EmulatedMemory& mem) -> bool {
        uint32_t lpTemplate = regs[1], hwndParent = regs[2], arm_dlgProc = regs[3];
        LPARAM initParam = (LPARAM)ReadStackArg(regs, mem, 0);
        auto tmpl = CopyDlgTemplate(mem, lpTemplate);
        bool has_captionok = FixupDlgTemplate(tmpl, wce_sysfont_name, wce_sysfont_height);
        HWND dlg = CreateDialogIndirectParamW(GetModuleHandleW(NULL),
            (LPCDLGTEMPLATEW)tmpl.data(), (HWND)(intptr_t)(int32_t)hwndParent, EmuDlgProc, initParam);
        if (dlg && arm_dlgProc) hwnd_dlgproc_map[dlg] = arm_dlgProc;
        if (dlg && has_captionok) {
            captionok_hwnds.insert(dlg);
            InstallCaptionOk(dlg);
            LOG(THUNK, "[THUNK]   Dialog HWND=0x%p has WS_EX_CAPTIONOKBTN\n", dlg);
        }
        regs[0] = (uint32_t)(uintptr_t)dlg;
        return true;
    });
    Thunk("DialogBoxIndirectParamW", 690, [this](uint32_t* regs, EmulatedMemory& mem) -> bool {
        uint32_t lpTemplate = regs[1], hwndParent = regs[2], arm_dlgProc = regs[3];
        LPARAM initParam = (LPARAM)ReadStackArg(regs, mem, 0);
        HWND parent = (HWND)(intptr_t)(int32_t)hwndParent;
        auto tmpl = CopyDlgTemplate(mem, lpTemplate);
        bool has_captionok = FixupDlgTemplate(tmpl, wce_sysfont_name, wce_sysfont_height);
        modal_dlg_ended = false;
        modal_dlg_result = 0;
        HWND dlg = CreateDialogIndirectParamW(GetModuleHandleW(NULL),
            (LPCDLGTEMPLATEW)tmpl.data(), parent, EmuDlgProc, initParam);
        if (dlg && arm_dlgProc) {
            hwnd_dlgproc_map[dlg] = arm_dlgProc;
            if (has_captionok) {
                captionok_hwnds.insert(dlg);
                InstallCaptionOk(dlg);
                LOG(THUNK, "[THUNK]   Modal dialog HWND=0x%p has WS_EX_CAPTIONOKBTN\n", dlg);
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
        LOG(THUNK, "[THUNK] EndDialog(hwnd=0x%p, result=%d)\n", dlg, (int)modal_dlg_result);
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
}
