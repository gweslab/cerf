/* String and locale thunks */
#define NOMINMAX
#include "../win32_thunks.h"
#include "../../log.h"
#include <cstdio>
#include <vector>

void Win32Thunks::RegisterStringHandlers() {
    /* Shared wide printf formatter: parse format string with args from ARM registers/stack */
    auto wprintf_format = [this](EmulatedMemory& mem, const std::wstring& fmt,
                                  uint32_t* args, int nargs) -> std::wstring {
        std::wstring result;
        int arg_idx = 0;
        for (size_t i = 0; i < fmt.size(); i++) {
            if (fmt[i] == L'%' && i + 1 < fmt.size()) {
                i++;
                /* Collect flags */
                bool left_align = false, zero_pad = false;
                while (i < fmt.size() && (fmt[i] == L'-' || fmt[i] == L'+' || fmt[i] == L' ' || fmt[i] == L'0')) {
                    if (fmt[i] == L'-') left_align = true;
                    if (fmt[i] == L'0') zero_pad = true;
                    i++;
                }
                /* Collect width */
                int width = 0;
                while (i < fmt.size() && fmt[i] >= L'0' && fmt[i] <= L'9') {
                    width = width * 10 + (fmt[i] - L'0'); i++;
                }
                /* Skip precision */
                if (i < fmt.size() && fmt[i] == L'.') {
                    i++;
                    while (i < fmt.size() && fmt[i] >= L'0' && fmt[i] <= L'9') i++;
                }
                /* Skip length modifier (l, h) */
                if (i < fmt.size() && (fmt[i] == L'l' || fmt[i] == L'h')) i++;
                if (i >= fmt.size()) break;
                if (arg_idx >= nargs) { result += L'?'; arg_idx++; continue; }
                wchar_t spec = fmt[i];
                if (spec == L'd' || spec == L'i') {
                    wchar_t buf[32]; _snwprintf_s(buf, _countof(buf), _TRUNCATE, L"%d", (int)args[arg_idx++]);
                    result += buf;
                } else if (spec == L'u') {
                    wchar_t buf[32]; _snwprintf_s(buf, _countof(buf), _TRUNCATE, L"%u", args[arg_idx++]);
                    result += buf;
                } else if (spec == L'x') {
                    wchar_t buf[32]; _snwprintf_s(buf, _countof(buf), _TRUNCATE, L"%x", args[arg_idx++]);
                    result += buf;
                } else if (spec == L'X') {
                    wchar_t buf[32]; _snwprintf_s(buf, _countof(buf), _TRUNCATE, L"%X", args[arg_idx++]);
                    result += buf;
                } else if (spec == L'c') {
                    result += (wchar_t)args[arg_idx++];
                } else if (spec == L's') {
                    if (args[arg_idx]) result += ReadWStringFromEmu(mem, args[arg_idx]);
                    arg_idx++;
                } else if (spec == L'%') {
                    result += L'%';
                } else { result += L'?'; arg_idx++; }
            } else result += fmt[i];
        }
        return result;
    };
    Thunk("wsprintfW", 56, [this, wprintf_format](uint32_t* regs, EmulatedMemory& mem) -> bool {
        uint32_t dst_addr = regs[0];
        std::wstring fmt = ReadWStringFromEmu(mem, regs[1]);
        uint32_t args[10];
        args[0] = regs[2]; args[1] = regs[3];
        for (int i = 2; i < 10; i++) args[i] = ReadStackArg(regs, mem, i - 2);
        std::wstring result = wprintf_format(mem, fmt, args, 10);
        for (size_t i = 0; i < result.size(); i++) mem.Write16(dst_addr + (uint32_t)i * 2, result[i]);
        mem.Write16(dst_addr + (uint32_t)result.size() * 2, 0);
        regs[0] = (uint32_t)result.size();
        return true;
    });
    Thunk("wcslen", 63, [this](uint32_t* regs, EmulatedMemory& mem) -> bool {
        uint32_t len = 0;
        while (mem.Read16(regs[0] + len * 2) != 0) len++;
        regs[0] = len; return true;
    });
    Thunk("wcscpy", 61, [this](uint32_t* regs, EmulatedMemory& mem) -> bool {
        uint32_t dst = regs[0], src = regs[1], i = 0; uint16_t ch;
        do { ch = mem.Read16(src + i*2); mem.Write16(dst + i*2, ch); i++; } while (ch);
        regs[0] = dst; return true;
    });
    Thunk("wcscat", 58, [this](uint32_t* regs, EmulatedMemory& mem) -> bool {
        uint32_t dst = regs[0], src = regs[1], dlen = 0;
        while (mem.Read16(dst + dlen*2)) dlen++;
        uint32_t i = 0; uint16_t ch;
        do { ch = mem.Read16(src + i*2); mem.Write16(dst + (dlen+i)*2, ch); i++; } while (ch);
        regs[0] = dst; return true;
    });
    Thunk("wcscmp", 60, [this](uint32_t* regs, EmulatedMemory& mem) -> bool {
        regs[0] = (uint32_t)wcscmp(ReadWStringFromEmu(mem,regs[0]).c_str(), ReadWStringFromEmu(mem,regs[1]).c_str());
        return true;
    });
    Thunk("wcsncpy", 66, [this](uint32_t* regs, EmulatedMemory& mem) -> bool {
        uint32_t dst = regs[0], src = regs[1], count = regs[2];
        for (uint32_t i = 0; i < count; i++) {
            uint16_t ch = mem.Read16(src + i*2); mem.Write16(dst + i*2, ch);
            if (ch == 0) { for (uint32_t j = i+1; j < count; j++) mem.Write16(dst+j*2, 0); break; }
        }
        regs[0] = dst; return true;
    });
    Thunk("wcsncmp", 65, [this](uint32_t* regs, EmulatedMemory& mem) -> bool {
        regs[0] = (uint32_t)wcsncmp(ReadWStringFromEmu(mem,regs[0]).c_str(), ReadWStringFromEmu(mem,regs[1]).c_str(), regs[2]);
        return true;
    });
    Thunk("_wcsicmp", 230, [this](uint32_t* regs, EmulatedMemory& mem) -> bool {
        regs[0] = (uint32_t)_wcsicmp(ReadWStringFromEmu(mem,regs[0]).c_str(), ReadWStringFromEmu(mem,regs[1]).c_str());
        return true;
    });
    Thunk("wcschr", 59, [this](uint32_t* regs, EmulatedMemory& mem) -> bool {
        uint32_t str = regs[0]; uint16_t ch = (uint16_t)regs[1];
        while (true) { uint16_t c = mem.Read16(str); if (c == ch) { regs[0] = str; return true; } if (c == 0) { regs[0] = 0; return true; } str += 2; }
    });
    Thunk("wcsrchr", 69, [this](uint32_t* regs, EmulatedMemory& mem) -> bool {
        uint32_t str = regs[0]; uint16_t ch = (uint16_t)regs[1]; uint32_t last = 0;
        while (true) { uint16_t c = mem.Read16(str); if (c == ch) last = str; if (c == 0) break; str += 2; }
        regs[0] = last; return true;
    });
    Thunk("wcsstr", 73, [this](uint32_t* regs, EmulatedMemory& mem) -> bool {
        std::wstring s1 = ReadWStringFromEmu(mem, regs[0]), s2 = ReadWStringFromEmu(mem, regs[1]);
        auto pos = s1.find(s2);
        regs[0] = (pos != std::wstring::npos) ? regs[0] + (uint32_t)(pos * 2) : 0; return true;
    });
    Thunk("_wtol", 78, [this](uint32_t* regs, EmulatedMemory& mem) -> bool {
        regs[0] = (uint32_t)_wtol(ReadWStringFromEmu(mem, regs[0]).c_str()); return true;
    });
    Thunk("wcstol", 1082, [this](uint32_t* regs, EmulatedMemory& mem) -> bool {
        regs[0] = (uint32_t)wcstol(ReadWStringFromEmu(mem, regs[0]).c_str(), NULL, regs[2]); return true;
    });
    Thunk("wcstoul", 1083, [this](uint32_t* regs, EmulatedMemory& mem) -> bool {
        regs[0] = (uint32_t)wcstoul(ReadWStringFromEmu(mem, regs[0]).c_str(), NULL, regs[2]); return true;
    });
    Thunk("towlower", 194, [](uint32_t* regs, EmulatedMemory&) -> bool { regs[0] = (uint32_t)towlower((wint_t)regs[0]); return true; });
    Thunk("towupper", 195, [](uint32_t* regs, EmulatedMemory&) -> bool { regs[0] = (uint32_t)towupper((wint_t)regs[0]); return true; });
    Thunk("iswctype", 193, [](uint32_t* regs, EmulatedMemory&) -> bool { regs[0] = (uint32_t)iswctype((wint_t)regs[0], regs[1]); return true; });
    Thunk("MultiByteToWideChar", 196, [this](uint32_t* regs, EmulatedMemory& mem) -> bool {
        std::string src = ReadStringFromEmu(mem, regs[2]);
        int needed = MultiByteToWideChar(regs[0], regs[1], src.c_str(), regs[3], NULL, 0);
        if (regs[4] != 0 && regs[5] > 0) {
            std::vector<wchar_t> buf(needed + 1);
            int ret = MultiByteToWideChar(regs[0], regs[1], src.c_str(), regs[3], buf.data(), needed);
            for (int i = 0; i < ret && i < (int)regs[5]; i++) mem.Write16(regs[4] + i*2, buf[i]);
            regs[0] = ret;
        } else regs[0] = needed;
        return true;
    });
    Thunk("WideCharToMultiByte", 197, [this](uint32_t* regs, EmulatedMemory& mem) -> bool {
        std::wstring src = ReadWStringFromEmu(mem, regs[2]);
        int needed = WideCharToMultiByte(regs[0], regs[1], src.c_str(), regs[3], NULL, 0, NULL, NULL);
        uint32_t dst_addr = ReadStackArg(regs, mem, 0), dst_size = ReadStackArg(regs, mem, 1);
        if (dst_addr && dst_size > 0) {
            std::vector<char> buf(needed + 1);
            int ret = WideCharToMultiByte(regs[0], regs[1], src.c_str(), regs[3], buf.data(), needed, NULL, NULL);
            for (int i = 0; i < ret && i < (int)dst_size; i++) mem.Write8(dst_addr + i, buf[i]);
            regs[0] = ret;
        } else regs[0] = needed;
        return true;
    });
    Thunk("FormatMessageW", 234, [](uint32_t* regs, EmulatedMemory&) -> bool { regs[0] = 0; return true; });
    Thunk("CompareStringW", 198, [](uint32_t* regs, EmulatedMemory&) -> bool { regs[0] = CSTR_EQUAL; return true; });
    Thunk("GetStringTypeW", 216, [](uint32_t* regs, EmulatedMemory&) -> bool { regs[0] = 0; return true; });
    Thunk("CharLowerW", 221, [](uint32_t* regs, EmulatedMemory&) -> bool {
        if ((regs[0] & 0xFFFF0000) == 0) regs[0] = (uint32_t)towlower(regs[0]); return true;
    });
    Thunk("CharUpperW", 224, [](uint32_t* regs, EmulatedMemory&) -> bool {
        if ((regs[0] & 0xFFFF0000) == 0) regs[0] = (uint32_t)towupper(regs[0]); return true;
    });
    Thunk("CharNextW", 226, [this](uint32_t* regs, EmulatedMemory& mem) -> bool {
        if (regs[0] && mem.Read16(regs[0]) != 0) regs[0] += 2; return true;
    });
    Thunk("lstrcmpW", 227, [this](uint32_t* regs, EmulatedMemory& mem) -> bool {
        regs[0] = (uint32_t)lstrcmpW(ReadWStringFromEmu(mem,regs[0]).c_str(), ReadWStringFromEmu(mem,regs[1]).c_str());
        return true;
    });
    Thunk("lstrcmpiW", 228, [this](uint32_t* regs, EmulatedMemory& mem) -> bool {
        regs[0] = (uint32_t)lstrcmpiW(ReadWStringFromEmu(mem,regs[0]).c_str(), ReadWStringFromEmu(mem,regs[1]).c_str()); return true;
    });
    Thunk("_wcsnicmp", 229, [this](uint32_t* regs, EmulatedMemory& mem) -> bool {
        regs[0] = (uint32_t)_wcsnicmp(ReadWStringFromEmu(mem,regs[0]).c_str(), ReadWStringFromEmu(mem,regs[1]).c_str(), regs[2]); return true;
    });
    Thunk("_wcsdup", 74, [this](uint32_t* regs, EmulatedMemory& mem) -> bool {
        std::wstring s = ReadWStringFromEmu(mem, regs[0]);
        static uint32_t next_dup = 0x43000000;
        uint32_t sz = ((uint32_t)s.size() + 1) * 2;
        mem.Alloc(next_dup, sz);
        for (size_t i = 0; i <= s.size(); i++) mem.Write16(next_dup + (uint32_t)i*2, s[i]);
        regs[0] = next_dup; next_dup += (sz + 0xFFF) & ~0xFFF;
        return true;
    });
    Thunk("wcstombs", 75, [this](uint32_t* regs, EmulatedMemory& mem) -> bool {
        std::wstring src = ReadWStringFromEmu(mem, regs[1]);
        uint32_t dst = regs[0], count = regs[2];
        for (uint32_t i = 0; i < count && i < (uint32_t)src.size(); i++) mem.Write8(dst+i, (uint8_t)src[i]);
        if (count > 0) mem.Write8(dst + std::min(count-1, (uint32_t)src.size()), 0);
        regs[0] = (uint32_t)src.size(); return true;
    });
    Thunk("mbstowcs", 76, [this](uint32_t* regs, EmulatedMemory& mem) -> bool {
        std::string src = ReadStringFromEmu(mem, regs[1]);
        uint32_t dst = regs[0], count = regs[2];
        for (uint32_t i = 0; i < count && i < (uint32_t)src.size(); i++) mem.Write16(dst+i*2, (uint16_t)(uint8_t)src[i]);
        if (count > 0) mem.Write16(dst + std::min(count-1, (uint32_t)src.size())*2, 0);
        regs[0] = (uint32_t)src.size(); return true;
    });
    Thunk("wcstok", 77, [](uint32_t* regs, EmulatedMemory&) -> bool { regs[0] = 0; return true; });
    thunk_handlers["wcspbrk"] = thunk_handlers["wcstok"];
    Thunk("_snwprintf", 1096, [this, wprintf_format](uint32_t* regs, EmulatedMemory& mem) -> bool {
        uint32_t dst = regs[0], count = regs[1];
        std::wstring fmt = ReadWStringFromEmu(mem, regs[2]);
        uint32_t args[10];
        args[0] = regs[3];
        for (int i = 1; i < 10; i++) args[i] = ReadStackArg(regs, mem, i - 1);
        std::wstring result = wprintf_format(mem, fmt, args, 10);
        uint32_t copy_len = std::min((uint32_t)result.size(), count > 0 ? count - 1 : 0u);
        for (uint32_t i = 0; i < copy_len; i++) mem.Write16(dst + i * 2, result[i]);
        if (count > 0) mem.Write16(dst + copy_len * 2, 0);
        regs[0] = (uint32_t)result.size();
        return true;
    });
    /* swprintf(dst, format, ...) — NO count param, unlike _snwprintf */
    Thunk("swprintf", 1097, [this, wprintf_format](uint32_t* regs, EmulatedMemory& mem) -> bool {
        uint32_t dst = regs[0];
        std::wstring fmt = ReadWStringFromEmu(mem, regs[1]);
        uint32_t args[10];
        args[0] = regs[2];
        args[1] = regs[3];
        for (int i = 2; i < 10; i++) args[i] = ReadStackArg(regs, mem, i - 2);
        std::wstring result = wprintf_format(mem, fmt, args, 10);
        for (uint32_t i = 0; i < (uint32_t)result.size(); i++) mem.Write16(dst + i * 2, result[i]);
        mem.Write16(dst + (uint32_t)result.size() * 2, 0);
        regs[0] = (uint32_t)result.size();
        return true;
    });
    thunk_handlers["swscanf"] = thunk_handlers["_snwprintf"]; /* stub — swscanf is rare */
    thunk_handlers["wvsprintfW"] = thunk_handlers["_snwprintf"];
    Thunk("sprintf", 1058, [](uint32_t* regs, EmulatedMemory&) -> bool { regs[0] = 0; return true; });
    /* StringCchPrintfW(pszDest, cchDest, pszFormat, ...) — safe wide printf */
    Thunk("StringCchPrintfW", 1699, [this, wprintf_format](uint32_t* regs, EmulatedMemory& mem) -> bool {
        uint32_t dst = regs[0], cch = regs[1];
        std::wstring fmt = ReadWStringFromEmu(mem, regs[2]);
        uint32_t args[10];
        args[0] = regs[3];
        for (int i = 1; i < 10; i++) args[i] = ReadStackArg(regs, mem, i - 1);
        std::wstring result = wprintf_format(mem, fmt, args, 10);
        if (!dst || cch == 0) { regs[0] = 0x80070057; return true; } /* E_INVALIDARG */
        uint32_t copy_len = std::min((uint32_t)result.size(), cch - 1);
        for (uint32_t i = 0; i < copy_len; i++) mem.Write16(dst + i * 2, result[i]);
        mem.Write16(dst + copy_len * 2, 0);
        regs[0] = (result.size() >= cch) ? 0x8007007A : 0; /* STRSAFE_E_INSUFFICIENT_BUFFER or S_OK */
        return true;
    });

    Thunk("StringCchCopyW", 1689, [this](uint32_t* regs, EmulatedMemory& mem) -> bool {
        uint32_t dst = regs[0], cch = regs[1], src_ptr = regs[2];
        if (!dst || cch == 0) { regs[0] = 0x80070057; return true; } /* E_INVALIDARG */
        std::wstring src = ReadWStringFromEmu(mem, src_ptr);
        uint32_t copy_len = std::min((uint32_t)src.size(), cch - 1);
        for (uint32_t i = 0; i < copy_len; i++) mem.Write16(dst + i * 2, src[i]);
        mem.Write16(dst + copy_len * 2, 0);
        regs[0] = (src.size() >= cch) ? 0x8007007A : 0; /* STRSAFE_E_INSUFFICIENT_BUFFER or S_OK */
        return true;
    });
    /* StringCchCopyExW(dst, cchDest, src, ppszDestEnd, pcchRemaining, dwFlags) */
    Thunk("StringCchCopyExW", 1691, [this](uint32_t* regs, EmulatedMemory& mem) -> bool {
        uint32_t dst = regs[0], cch = regs[1], src_ptr = regs[2], ppEnd = regs[3];
        uint32_t pcchRemaining = ReadStackArg(regs, mem, 0);
        if (!dst || cch == 0) { regs[0] = 0x80070057; return true; }
        std::wstring src = ReadWStringFromEmu(mem, src_ptr);
        uint32_t copy_len = std::min((uint32_t)src.size(), cch - 1);
        for (uint32_t i = 0; i < copy_len; i++) mem.Write16(dst + i * 2, src[i]);
        mem.Write16(dst + copy_len * 2, 0);
        if (ppEnd) mem.Write32(ppEnd, dst + copy_len * 2);
        if (pcchRemaining) mem.Write32(pcchRemaining, cch - copy_len);
        regs[0] = (src.size() >= cch) ? 0x8007007A : 0;
        return true;
    });
    Thunk("StringCchCatW", 1693, [this](uint32_t* regs, EmulatedMemory& mem) -> bool {
        uint32_t dst = regs[0], cch = regs[1], src_ptr = regs[2];
        if (!dst || cch == 0) { regs[0] = 0x80070057; return true; }
        std::wstring existing = ReadWStringFromEmu(mem, dst);
        std::wstring src = ReadWStringFromEmu(mem, src_ptr);
        uint32_t cur_len = (uint32_t)existing.size();
        uint32_t avail = (cur_len < cch) ? cch - cur_len - 1 : 0;
        uint32_t copy_len = std::min((uint32_t)src.size(), avail);
        for (uint32_t i = 0; i < copy_len; i++) mem.Write16(dst + (cur_len + i) * 2, src[i]);
        mem.Write16(dst + (cur_len + copy_len) * 2, 0);
        regs[0] = (src.size() > avail) ? 0x8007007A : 0;
        return true;
    });

    Thunk("StringCchLengthW", 1748, [this](uint32_t* regs, EmulatedMemory& mem) -> bool {
        uint32_t psz = regs[0], cchMax = regs[1], pcch_out = regs[2];
        if (!psz) { regs[0] = 0x80070057; return true; } /* STRSAFE_E_INVALID_PARAMETER */
        uint32_t len = 0;
        for (; len < cchMax; len++) { if (mem.Read16(psz + len * 2) == 0) break; }
        if (len >= cchMax) { if (pcch_out) mem.Write32(pcch_out, 0); regs[0] = 0x8007007A; return true; }
        if (pcch_out) mem.Write32(pcch_out, len);
        regs[0] = 0; /* S_OK */
        return true;
    });
    Thunk("LCMapStringW", 199, [](uint32_t* regs, EmulatedMemory&) -> bool {
        LOG(THUNK, "[THUNK] LCMapStringW(locale=0x%X, flags=0x%X, src=0x%08X, srcLen=%d) -> 0 (stub)\n",
               regs[0], regs[1], regs[2], (int32_t)regs[3]);
        regs[0] = 0; return true;
    });
    Thunk("CharLowerBuffW", 222, [this](uint32_t* regs, EmulatedMemory& mem) -> bool {
        uint32_t addr = regs[0], len = regs[1];
        for (uint32_t i = 0; i < len; i++) {
            uint16_t ch = mem.Read16(addr + i * 2);
            mem.Write16(addr + i * 2, (uint16_t)towlower(ch));
        }
        regs[0] = len; return true;
    });
    Thunk("CharUpperBuffW", 223, [this](uint32_t* regs, EmulatedMemory& mem) -> bool {
        uint32_t addr = regs[0], len = regs[1];
        for (uint32_t i = 0; i < len; i++) {
            uint16_t ch = mem.Read16(addr + i * 2);
            mem.Write16(addr + i * 2, (uint16_t)towupper(ch));
        }
        regs[0] = len; return true;
    });
    Thunk("_itow", 1026, [this](uint32_t* regs, EmulatedMemory& mem) -> bool {
        int value = (int32_t)regs[0];
        uint32_t buf_addr = regs[1];
        int radix = regs[2];
        wchar_t buf[34];
        _itow(value, buf, radix);
        for (int i = 0; buf[i]; i++) mem.Write16(buf_addr + i * 2, buf[i]);
        mem.Write16(buf_addr + (uint32_t)wcslen(buf) * 2, 0);
        regs[0] = buf_addr;
        return true;
    });
    Thunk("strcpy", 1066, [this](uint32_t* regs, EmulatedMemory& mem) -> bool {
        uint32_t dst = regs[0], src = regs[1];
        uint32_t i = 0;
        uint8_t c;
        do { c = mem.Read8(src + i); mem.Write8(dst + i, c); i++; } while (c);
        regs[0] = dst;
        return true;
    });
    Thunk("strlen", 1068, [this](uint32_t* regs, EmulatedMemory& mem) -> bool {
        uint32_t addr = regs[0], len = 0;
        while (mem.Read8(addr + len)) len++;
        regs[0] = len;
        return true;
    });
    Thunk("strncmp", 1070, [this](uint32_t* regs, EmulatedMemory& mem) -> bool {
        uint32_t s1 = regs[0], s2 = regs[1], n = regs[2];
        int result = 0;
        for (uint32_t i = 0; i < n; i++) {
            uint8_t c1 = mem.Read8(s1 + i), c2 = mem.Read8(s2 + i);
            if (c1 != c2) { result = (int)c1 - (int)c2; break; }
            if (c1 == 0) break;
        }
        regs[0] = (uint32_t)(int32_t)result;
        return true;
    });
    Thunk("strcmp", 1065, [this](uint32_t* regs, EmulatedMemory& mem) -> bool {
        uint32_t s1 = regs[0], s2 = regs[1];
        int result = 0;
        for (uint32_t i = 0; ; i++) {
            uint8_t c1 = mem.Read8(s1 + i), c2 = mem.Read8(s2 + i);
            if (c1 != c2) { result = (int)c1 - (int)c2; break; }
            if (c1 == 0) break;
        }
        regs[0] = (uint32_t)(int32_t)result; return true;
    });
    Thunk("strstr", 1072, [this](uint32_t* regs, EmulatedMemory& mem) -> bool {
        std::string s1 = ReadStringFromEmu(mem, regs[0]);
        std::string s2 = ReadStringFromEmu(mem, regs[1]);
        auto pos = s1.find(s2);
        regs[0] = (pos != std::string::npos) ? regs[0] + (uint32_t)pos : 0; return true;
    });
    Thunk("atoi", 993, [this](uint32_t* regs, EmulatedMemory& mem) -> bool {
        std::string s = ReadStringFromEmu(mem, regs[0]);
        regs[0] = (uint32_t)atoi(s.c_str()); return true;
    });
    Thunk("IsValidCodePage", 185, [](uint32_t* regs, EmulatedMemory&) -> bool {
        regs[0] = IsValidCodePage(regs[0]); return true;
    });
    Thunk("IsDBCSLeadByte", 191, [](uint32_t* regs, EmulatedMemory&) -> bool {
        regs[0] = IsDBCSLeadByte((BYTE)regs[0]); return true;
    });
    Thunk("GetStringTypeExW", 217, [](uint32_t* regs, EmulatedMemory&) -> bool {
        regs[0] = 0; return true;
    });
    /* Ordinal-only entries (name mapping, no handler) */
    ThunkOrdinal("wvsprintfW", 57);
    Thunk("wcsncat", 64, [this](uint32_t* regs, EmulatedMemory& mem) -> bool {
        uint32_t dst = regs[0], src = regs[1], count = regs[2];
        uint32_t dlen = 0;
        while (mem.Read16(dst + dlen * 2)) dlen++;
        uint32_t i = 0;
        while (i < count) {
            uint16_t ch = mem.Read16(src + i * 2);
            mem.Write16(dst + (dlen + i) * 2, ch);
            if (ch == 0) break;
            i++;
        }
        mem.Write16(dst + (dlen + i) * 2, 0);
        regs[0] = dst;
        return true;
    });
    ThunkOrdinal("wcspbrk", 68);
    ThunkOrdinal("swprintf", 1097);
    ThunkOrdinal("swscanf", 1098);
}
