/* Dialog template helpers: compute size, copy, and fixup DLGTEMPLATE.
   Split from dialog.cpp to keep files under 300 lines. */
#define NOMINMAX
#include "dialog_template.h"
#include "../../log.h"

/* Helper: compute size of a DLGTEMPLATE (with all items) in emulated memory. */
uint32_t ComputeDlgTemplateSize(EmulatedMemory& mem, uint32_t addr) {
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

std::vector<uint8_t> CopyDlgTemplate(EmulatedMemory& mem, uint32_t addr) {
    uint32_t size = ComputeDlgTemplateSize(mem, addr);
    std::vector<uint8_t> buf(size);
    for (uint32_t i = 0; i < size; i++) buf[i] = mem.Read8(addr + i);
    return buf;
}

/* Strip WinCE-only styles from a copied DLGTEMPLATE buffer.
   Also patches the dialog font: WinCE "System" → configured sysfont (e.g. Tahoma).
   If DS_SETFONT is absent, adds it with the WinCE system font so child controls
   match the WinCE appearance instead of using the desktop "System" bitmap font.
   Returns fixup result with original WinCE styles. */
DlgFixupResult FixupDlgTemplate(std::vector<uint8_t>& tmpl, const std::wstring& sysfont_name) {
    DlgFixupResult result = {};
    if (tmpl.size() < 10) return result;
    /* DLGTEMPLATE: offset 0 = style (DWORD), offset 4 = dwExtendedStyle (DWORD) */
    uint32_t style   = *(uint32_t*)&tmpl[0];
    uint32_t exStyle = *(uint32_t*)&tmpl[4];
    /* Save original WinCE styles before modification */
    result.wce_style = style;
    result.wce_exstyle = exStyle;
    result.had_captionok = (exStyle & 0x80000000u) != 0;
    result.is_child = (style & WS_CHILD) != 0;
    exStyle &= ~0x80000000u;   /* strip WS_EX_CAPTIONOKBTN — we render it ourselves */
    /* Only convert non-child dialogs to WS_POPUP.  Child dialogs (e.g. property
       pages inside a property sheet tab control) must keep WS_CHILD so they
       position correctly inside their parent. */
    if (!result.is_child) {
        style &= ~(uint32_t)(WS_OVERLAPPED | WS_THICKFRAME |
                              WS_MINIMIZEBOX | WS_MAXIMIZEBOX | WS_CAPTION);
        style |= WS_POPUP;
    }
    *(uint32_t*)&tmpl[0] = style;
    *(uint32_t*)&tmpl[4] = exStyle;

    /* Detect DLGTEMPLATEEX vs DLGTEMPLATE.
       DLGTEMPLATEEX has signature 0xFFFF at offset 2, dlgVer=1 at offset 0. */
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

    /* Locate the font field in the template. */
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
        /* DS_SETFONT present: keep point size, replace font name. */
        p += 2; /* skip point size (unchanged) */
        size_t name_start = p;
        while (p + 2 <= tmpl.size() && *(uint16_t*)&tmpl[p]) p += 2;
        p += 2;
        size_t old_items = (p + 3) & ~(size_t)3;

        size_t new_name_bytes = (sysfont_name.size() + 1) * 2;
        size_t new_name_end = name_start + new_name_bytes;
        size_t new_items = (new_name_end + 3) & ~(size_t)3;
        size_t new_pad = new_items - new_name_end;

        tmpl.erase(tmpl.begin() + name_start, tmpl.begin() + old_items);
        tmpl.insert(tmpl.begin() + name_start, new_name_bytes + new_pad, 0);
        for (size_t i = 0; i < sysfont_name.size(); i++)
            *(uint16_t*)&tmpl[name_start + i * 2] = (uint16_t)sysfont_name[i];
        *(uint16_t*)&tmpl[name_start + sysfont_name.size() * 2] = 0;
    } else {
        /* No DS_SETFONT: add it with 8pt WinCE system font. */
        style |= DS_SETFONT;
        *(uint32_t*)&tmpl[0] = style;
        size_t old_items = (p + 3) & ~(size_t)3;

        size_t new_name_bytes = (sysfont_name.size() + 1) * 2;
        size_t font_data_size = 2 + new_name_bytes;
        size_t new_font_end = p + font_data_size;
        size_t new_items = (new_font_end + 3) & ~(size_t)3;
        size_t new_pad = new_items - new_font_end;

        tmpl.erase(tmpl.begin() + p, tmpl.begin() + old_items);
        tmpl.insert(tmpl.begin() + p, font_data_size + new_pad, 0);
        *(uint16_t*)&tmpl[p] = 8;
        for (size_t i = 0; i < sysfont_name.size(); i++)
            *(uint16_t*)&tmpl[p + 2 + i * 2] = (uint16_t)sysfont_name[i];
        *(uint16_t*)&tmpl[p + 2 + sysfont_name.size() * 2] = 0;
    }
    return result;
}
