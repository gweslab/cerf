/* GDI thunks: fonts, text metrics, DrawTextW, ExtTextOutW */
#include "../win32_thunks.h"
#include "../../log.h"
#include <cstdio>

/* Read WinCE system font configuration from HKLM\System\GDI\SYSFNT registry.
   This is how real WinCE configures the System/default GUI font. */
void Win32Thunks::InitWceSysFont() {
    LoadRegistry();
    auto key_it = registry.find(L"hklm\\system\\gdi\\sysfnt");
    if (key_it == registry.end()) return;
    auto& vals = key_it->second.values;
    /* "Nm" = font name (REG_SZ) */
    auto nm_it = vals.find(L"Nm");
    if (nm_it != vals.end() && nm_it->second.type == REG_SZ && nm_it->second.data.size() >= 2) {
        wce_sysfont_name.clear();
        const wchar_t* p = (const wchar_t*)nm_it->second.data.data();
        size_t len = nm_it->second.data.size() / 2;
        for (size_t i = 0; i < len && p[i]; i++) wce_sysfont_name += p[i];
    }
    /* "Ht" = height (REG_DWORD, negative = point size) */
    auto ht_it = vals.find(L"Ht");
    if (ht_it != vals.end() && ht_it->second.type == REG_DWORD && ht_it->second.data.size() >= 4)
        wce_sysfont_height = *(LONG*)ht_it->second.data.data();
    /* "Wt" = weight (REG_DWORD, 400=normal, 700=bold) */
    auto wt_it = vals.find(L"Wt");
    if (wt_it != vals.end() && wt_it->second.type == REG_DWORD && wt_it->second.data.size() >= 4)
        wce_sysfont_weight = *(LONG*)wt_it->second.data.data();
    LOG(API, "[API] WinCE system font: '%ls' height=%d weight=%d\n",
        wce_sysfont_name.c_str(), wce_sysfont_height, wce_sysfont_weight);
}

void Win32Thunks::RegisterGdiTextHandlers() {
    Thunk("CreateFontIndirectW", 895, [this](uint32_t* regs, EmulatedMemory& mem) -> bool {
        /* LOGFONTW is 92 bytes, identical layout on 32-bit WinCE and 64-bit Windows */
        uint32_t p = regs[0];
        LOGFONTW lf = {};
        lf.lfHeight         = (LONG)mem.Read32(p);
        lf.lfWidth          = (LONG)mem.Read32(p + 4);
        lf.lfEscapement     = (LONG)mem.Read32(p + 8);
        lf.lfOrientation    = (LONG)mem.Read32(p + 12);
        lf.lfWeight         = (LONG)mem.Read32(p + 16);
        lf.lfItalic         = mem.Read8(p + 20);
        lf.lfUnderline      = mem.Read8(p + 21);
        lf.lfStrikeOut      = mem.Read8(p + 22);
        lf.lfCharSet        = mem.Read8(p + 23);
        lf.lfOutPrecision   = mem.Read8(p + 24);
        lf.lfClipPrecision  = mem.Read8(p + 25);
        lf.lfQuality        = mem.Read8(p + 26);
        lf.lfPitchAndFamily = mem.Read8(p + 27);
        for (int i = 0; i < 32; i++) {
            lf.lfFaceName[i] = mem.Read16(p + 28 + i * 2);
            if (!lf.lfFaceName[i]) break;
        }
        /* WinCE "System" font is configured via HKLM\System\GDI\SYSFNT registry.
           On desktop Windows, "System" is an old bitmap font that looks wrong.
           Remap to the device's configured system font (typically Tahoma). */
        if (_wcsicmp(lf.lfFaceName, L"System") == 0) {
            wcscpy_s(lf.lfFaceName, wce_sysfont_name.c_str());
        }
        LOG(API, "[API] CreateFontIndirectW('%ls', h=%d, w=%d, wt=%d)\n",
            lf.lfFaceName, lf.lfHeight, lf.lfWidth, lf.lfWeight);
        regs[0] = (uint32_t)(uintptr_t)CreateFontIndirectW(&lf);
        return true;
    });
    Thunk("GetTextMetricsW", 898, [this](uint32_t* regs, EmulatedMemory& mem) -> bool {
        HDC hdc = (HDC)(intptr_t)(int32_t)regs[0];
        TEXTMETRICW tm; BOOL ret = GetTextMetricsW(hdc, &tm);
        if (ret && regs[1]) {
            mem.Write32(regs[1]+0, tm.tmHeight); mem.Write32(regs[1]+4, tm.tmAscent);
            mem.Write32(regs[1]+8, tm.tmDescent); mem.Write32(regs[1]+12, tm.tmInternalLeading);
            mem.Write32(regs[1]+16, tm.tmExternalLeading); mem.Write32(regs[1]+20, tm.tmAveCharWidth);
            mem.Write32(regs[1]+24, tm.tmMaxCharWidth); mem.Write32(regs[1]+28, tm.tmWeight);
            mem.Write32(regs[1]+32, tm.tmOverhang); mem.Write32(regs[1]+36, tm.tmDigitizedAspectX);
            mem.Write32(regs[1]+40, tm.tmDigitizedAspectY);
            mem.Write16(regs[1]+44, tm.tmFirstChar); mem.Write16(regs[1]+46, tm.tmLastChar);
            mem.Write16(regs[1]+48, tm.tmDefaultChar); mem.Write16(regs[1]+50, tm.tmBreakChar);
            mem.Write8(regs[1]+52, tm.tmItalic); mem.Write8(regs[1]+53, tm.tmUnderlined);
            mem.Write8(regs[1]+54, tm.tmStruckOut); mem.Write8(regs[1]+55, tm.tmPitchAndFamily);
            mem.Write8(regs[1]+56, tm.tmCharSet);
        }
        regs[0] = ret; return true;
    });
    Thunk("DrawTextW", 945, [this](uint32_t* regs, EmulatedMemory& mem) -> bool {
        HDC hdc = (HDC)(intptr_t)(int32_t)regs[0];
        std::wstring text = ReadWStringFromEmu(mem, regs[1]);
        int count = (int32_t)regs[2]; uint32_t rect_addr = regs[3];
        uint32_t format = ReadStackArg(regs, mem, 0);
        RECT rc; rc.left = (int32_t)mem.Read32(rect_addr); rc.top = (int32_t)mem.Read32(rect_addr+4);
        rc.right = (int32_t)mem.Read32(rect_addr+8); rc.bottom = (int32_t)mem.Read32(rect_addr+12);
        int ret = ::DrawTextW(hdc, text.c_str(), count, &rc, format);
        mem.Write32(rect_addr, (uint32_t)rc.left); mem.Write32(rect_addr+4, (uint32_t)rc.top);
        mem.Write32(rect_addr+8, (uint32_t)rc.right); mem.Write32(rect_addr+12, (uint32_t)rc.bottom);
        regs[0] = (uint32_t)ret; return true;
    });
    Thunk("SetTextAlign", 1654, [](uint32_t* regs, EmulatedMemory&) -> bool { regs[0] = SetTextAlign((HDC)(intptr_t)(int32_t)regs[0], regs[1]); return true; });
    Thunk("GetTextAlign", 1655, [](uint32_t* regs, EmulatedMemory&) -> bool { regs[0] = GetTextAlign((HDC)(intptr_t)(int32_t)regs[0]); return true; });
    /* ExtTextOutW(hdc, x, y, options, lprc, lpString, nCount, lpDx)
       r0=hdc, r1=x, r2=y, r3=options, stack[0]=lprc, stack[1]=lpString,
       stack[2]=nCount, stack[3]=lpDx */
    Thunk("ExtTextOutW", 896, [this](uint32_t* regs, EmulatedMemory& mem) -> bool {
        LOG(API, "[API] ExtTextOutW CALLED r0=0x%08X r1=%d r2=%d r3=0x%X\n", regs[0], regs[1], regs[2], regs[3]);
        HDC hdc = (HDC)(intptr_t)(int32_t)regs[0];
        int x = (int)regs[1], y = (int)regs[2];
        UINT options = regs[3];
        uint32_t lprc_addr = ReadStackArg(regs, mem, 0);
        uint32_t lpStr_addr = ReadStackArg(regs, mem, 1);
        UINT count = ReadStackArg(regs, mem, 2);
        uint32_t lpDx_addr = ReadStackArg(regs, mem, 3);
        RECT rc = {};
        RECT* prc = NULL;
        if (lprc_addr) {
            rc.left = (int32_t)mem.Read32(lprc_addr);
            rc.top = (int32_t)mem.Read32(lprc_addr + 4);
            rc.right = (int32_t)mem.Read32(lprc_addr + 8);
            rc.bottom = (int32_t)mem.Read32(lprc_addr + 12);
            prc = &rc;
        }
        std::wstring text;
        if (lpStr_addr && count > 0) {
            text.resize(count);
            for (UINT i = 0; i < count; i++)
                text[i] = (wchar_t)mem.Read16(lpStr_addr + i * 2);
        }
        std::vector<INT> dx;
        INT* pdx = NULL;
        if (lpDx_addr && count > 0) {
            dx.resize(count);
            for (UINT i = 0; i < count; i++)
                dx[i] = (INT)mem.Read32(lpDx_addr + i * 4);
            pdx = dx.data();
        }
        BOOL ret = ExtTextOutW(hdc, x, y, options, prc,
                               text.empty() ? NULL : text.c_str(), count, pdx);
        if (!text.empty() && count > 0 && count < 200) {
            LOG(API, "[API] ExtTextOutW(hdc=0x%p, x=%d, y=%d, opts=0x%X, count=%d, text='%ls') -> %d\n",
                hdc, x, y, options, count, text.c_str(), ret);
        }
        regs[0] = ret;
        return true;
    });
    /* GetTextExtentExPointW(hdc, lpszStr, cchString, nMaxExtent,
       lpnFit, alpDx, lpSize)
       r0=hdc, r1=lpszStr, r2=cchString, r3=nMaxExtent,
       stack[0]=lpnFit, stack[1]=alpDx, stack[2]=lpSize */
    Thunk("GetTextExtentExPointW", 897, [this](uint32_t* regs, EmulatedMemory& mem) -> bool {
        HDC hdc = (HDC)(intptr_t)(int32_t)regs[0];
        uint32_t str_addr = regs[1];
        int cch = (int)regs[2];
        int maxExtent = (int)regs[3];
        uint32_t pnFit_addr = ReadStackArg(regs, mem, 0);
        uint32_t alpDx_addr = ReadStackArg(regs, mem, 1);
        uint32_t pSize_addr = ReadStackArg(regs, mem, 2);
        std::wstring text;
        if (str_addr && cch > 0) {
            text.resize(cch);
            for (int i = 0; i < cch; i++)
                text[i] = (wchar_t)mem.Read16(str_addr + i * 2);
        }
        int nFit = 0;
        std::vector<INT> dx(cch > 0 ? cch : 1);
        SIZE sz = {};
        BOOL ret = GetTextExtentExPointW(hdc, text.c_str(), cch, maxExtent,
                                          &nFit, dx.data(), &sz);
        if (ret) {
            if (pnFit_addr) mem.Write32(pnFit_addr, (uint32_t)nFit);
            if (alpDx_addr) {
                for (int i = 0; i < nFit; i++)
                    mem.Write32(alpDx_addr + i * 4, (uint32_t)dx[i]);
            }
            if (pSize_addr) {
                mem.Write32(pSize_addr, (uint32_t)sz.cx);
                mem.Write32(pSize_addr + 4, (uint32_t)sz.cy);
            }
        }
        regs[0] = ret;
        return true;
    });
    Thunk("EnumFontFamiliesW", 965, [this](uint32_t* regs, EmulatedMemory& mem) -> bool {
        uint32_t arm_callback = regs[2];
        uint32_t arm_lparam = regs[3];
        LOG(API, "[API] EnumFontFamiliesW(hdc=0x%08X, proc=0x%08X)\n", regs[0], arm_callback);
        if (!callback_executor || !arm_callback) { regs[0] = 1; return true; }

        /* Scratch area for LOGFONT (92 bytes) + TEXTMETRIC (60 bytes) in ARM memory */
        static uint32_t scratch = 0x3F004000;
        if (!mem.IsValid(scratch)) mem.Alloc(scratch, 0x1000);
        uint32_t lf_addr = scratch;
        uint32_t tm_addr = scratch + 96;

        /* Provide a hardcoded Tahoma font — avoids native GDI calls that may
           fail in deeply nested callback context. WinCE apps just need to know
           at least one font exists. */
        static const wchar_t* font_names[] = { L"Tahoma", L"Arial", L"Courier New" };
        int result = 1;
        for (int f = 0; f < 3 && result != 0; f++) {
            /* Zero-fill both structures */
            for (uint32_t i = 0; i < 92; i++) mem.Write8(lf_addr + i, 0);
            for (uint32_t i = 0; i < 60; i++) mem.Write8(tm_addr + i, 0);
            /* LOGFONTW: height=-13, weight=400, charset=1(DEFAULT), face name */
            mem.Write32(lf_addr + 0, (uint32_t)-13);  /* lfHeight */
            mem.Write32(lf_addr + 16, 400);            /* lfWeight (FW_NORMAL) */
            mem.Write8(lf_addr + 23, 1);               /* lfCharSet (DEFAULT_CHARSET) */
            mem.Write8(lf_addr + 27, 0x22);            /* lfPitchAndFamily (VARIABLE_PITCH | FF_SWISS) */
            const wchar_t* name = font_names[f];
            for (int i = 0; name[i] && i < 31; i++) mem.Write16(lf_addr + 28 + i * 2, name[i]);
            /* TEXTMETRICW: reasonable defaults */
            mem.Write32(tm_addr + 0, 16);   /* tmHeight */
            mem.Write32(tm_addr + 4, 13);   /* tmAscent */
            mem.Write32(tm_addr + 8, 3);    /* tmDescent */
            mem.Write32(tm_addr + 20, 7);   /* tmAveCharWidth */
            mem.Write32(tm_addr + 24, 14);  /* tmMaxCharWidth */
            mem.Write32(tm_addr + 28, 400); /* tmWeight */
            mem.Write16(tm_addr + 44, 0x20); /* tmFirstChar */
            mem.Write16(tm_addr + 46, 0xFFFD); /* tmLastChar */
            mem.Write8(tm_addr + 55, 0x22); /* tmPitchAndFamily */
            mem.Write8(tm_addr + 56, 1);    /* tmCharSet (DEFAULT_CHARSET) */

            uint32_t args[4] = { lf_addr, tm_addr, 4 /* TRUETYPE_FONTTYPE */, arm_lparam };
            LOG(API, "[API] EnumFontFamiliesW: callback for '%ls'\n", name);
            result = (int)callback_executor(arm_callback, args, 4);
            LOG(API, "[API] EnumFontFamiliesW: callback returned %d\n", result);
        }
        regs[0] = (uint32_t)result;
        return true;
    });
    Thunk("GetTextFaceW", 967, [this](uint32_t* regs, EmulatedMemory& mem) -> bool {
        HDC hdc = (HDC)(intptr_t)(int32_t)regs[0];
        int nCount = (int)regs[1];
        uint32_t buf_addr = regs[2];
        wchar_t face[256] = {};
        int ret = ::GetTextFaceW(hdc, 256, face);
        LOG(API, "[API] GetTextFaceW(hdc=0x%08X, nCount=%d) -> '%ls' (%d)\n",
               regs[0], nCount, face, ret);
        if (buf_addr && nCount > 0) {
            int copyLen = (ret < nCount) ? ret : nCount - 1;
            for (int i = 0; i < copyLen; i++)
                mem.Write16(buf_addr + i * 2, face[i]);
            mem.Write16(buf_addr + copyLen * 2, 0);
        }
        regs[0] = (uint32_t)ret;
        return true;
    });
    Thunk("AddFontResourceW", 893, [](uint32_t* regs, EmulatedMemory&) -> bool {
        LOG(API, "[API] [STUB] AddFontResourceW -> 1\n");
        regs[0] = 1; return true;
    });
}
