/* String thunks: basic wcs/str operations, char conversion, comparisons */
#define NOMINMAX
#include "../win32_thunks.h"
#include "../../log.h"
#include <cstdio>
#include <vector>

void Win32Thunks::RegisterStringHandlers() {
    Thunk("wcslen", 63, [this](uint32_t* regs, EmulatedMemory& mem) -> bool {
        std::wstring s = ReadWStringFromEmu(mem, regs[0]);
        regs[0] = (uint32_t)s.size();
        return true;
    });
    Thunk("wcscpy", 61, [this](uint32_t* regs, EmulatedMemory& mem) -> bool {
        std::wstring s = ReadWStringFromEmu(mem, regs[1]);
        for (size_t i = 0; i <= s.size(); i++) mem.Write16(regs[0] + (uint32_t)i * 2, s[i]);
        regs[0] = regs[0]; return true;
    });
    Thunk("wcscat", 58, [this](uint32_t* regs, EmulatedMemory& mem) -> bool {
        std::wstring dst_str = ReadWStringFromEmu(mem, regs[0]);
        std::wstring src_str = ReadWStringFromEmu(mem, regs[1]);
        uint32_t off = (uint32_t)dst_str.size();
        for (size_t i = 0; i <= src_str.size(); i++) mem.Write16(regs[0] + (off + (uint32_t)i) * 2, src_str[i]);
        return true;
    });
    Thunk("wcscmp", 60, [this](uint32_t* regs, EmulatedMemory& mem) -> bool {
        std::wstring a = ReadWStringFromEmu(mem, regs[0]), b = ReadWStringFromEmu(mem, regs[1]);
        regs[0] = (uint32_t)(int32_t)a.compare(b); return true;
    });
    Thunk("wcsncpy", 66, [this](uint32_t* regs, EmulatedMemory& mem) -> bool {
        uint32_t dst = regs[0], src = regs[1], count = regs[2];
        uint32_t i = 0;
        for (; i < count; i++) {
            uint16_t ch = mem.Read16(src + i * 2);
            mem.Write16(dst + i * 2, ch);
            if (ch == 0) break;
        }
        for (; i < count; i++) mem.Write16(dst + i * 2, 0);
        regs[0] = dst; return true;
    });
    Thunk("wcsncmp", 65, [this](uint32_t* regs, EmulatedMemory& mem) -> bool {
        std::wstring a = ReadWStringFromEmu(mem, regs[0]), b = ReadWStringFromEmu(mem, regs[1]);
        regs[0] = (uint32_t)(int32_t)a.compare(0, regs[2], b, 0, regs[2]); return true;
    });
    Thunk("_wcsicmp", 230, [this](uint32_t* regs, EmulatedMemory& mem) -> bool {
        std::wstring a = ReadWStringFromEmu(mem, regs[0]), b = ReadWStringFromEmu(mem, regs[1]);
        regs[0] = (uint32_t)(int32_t)_wcsicmp(a.c_str(), b.c_str()); return true;
    });
    Thunk("wcschr", 59, [this](uint32_t* regs, EmulatedMemory& mem) -> bool {
        std::wstring s = ReadWStringFromEmu(mem, regs[0]);
        auto pos = s.find((wchar_t)regs[1]);
        regs[0] = (pos != std::wstring::npos) ? regs[0] + (uint32_t)pos * 2 : 0; return true;
    });
    Thunk("wcsrchr", 69, [this](uint32_t* regs, EmulatedMemory& mem) -> bool {
        std::wstring s = ReadWStringFromEmu(mem, regs[0]);
        auto pos = s.rfind((wchar_t)regs[1]);
        regs[0] = (pos != std::wstring::npos) ? regs[0] + (uint32_t)pos * 2 : 0;
        return true;
    });
    Thunk("wcsstr", 73, [this](uint32_t* regs, EmulatedMemory& mem) -> bool {
        std::wstring a = ReadWStringFromEmu(mem, regs[0]), b = ReadWStringFromEmu(mem, regs[1]);
        auto pos = a.find(b);
        regs[0] = (pos != std::wstring::npos) ? regs[0] + (uint32_t)pos * 2 : 0; return true;
    });
    Thunk("_wtol", 78, [this](uint32_t* regs, EmulatedMemory& mem) -> bool {
        std::wstring s = ReadWStringFromEmu(mem, regs[0]);
        regs[0] = (uint32_t)wcstol(s.c_str(), NULL, 10); return true;
    });
    Thunk("wcstol", 1082, [this](uint32_t* regs, EmulatedMemory& mem) -> bool {
        std::wstring s = ReadWStringFromEmu(mem, regs[0]);
        regs[0] = (uint32_t)wcstol(s.c_str(), NULL, regs[2]); return true;
    });
    Thunk("wcstoul", 1083, [this](uint32_t* regs, EmulatedMemory& mem) -> bool {
        std::wstring s = ReadWStringFromEmu(mem, regs[0]);
        regs[0] = (uint32_t)wcstoul(s.c_str(), NULL, regs[2]); return true;
    });
    Thunk("towlower", 194, [](uint32_t* regs, EmulatedMemory&) -> bool { regs[0] = (uint32_t)towlower((wint_t)regs[0]); return true; });
    Thunk("towupper", 195, [](uint32_t* regs, EmulatedMemory&) -> bool { regs[0] = (uint32_t)towupper((wint_t)regs[0]); return true; });
    Thunk("iswctype", 193, [](uint32_t* regs, EmulatedMemory&) -> bool { regs[0] = (uint32_t)iswctype((wint_t)regs[0], regs[1]); return true; });
    Thunk("MultiByteToWideChar", 196, [this](uint32_t* regs, EmulatedMemory& mem) -> bool {
        std::string src = ReadStringFromEmu(mem, regs[2]);
        uint32_t dst_addr = ReadStackArg(regs, mem, 0), dst_size = ReadStackArg(regs, mem, 1);
        int needed = MultiByteToWideChar(regs[0], regs[1], src.c_str(), regs[3], NULL, 0);
        if (dst_addr != 0 && dst_size > 0) {
            std::vector<wchar_t> buf(needed + 1);
            int ret = MultiByteToWideChar(regs[0], regs[1], src.c_str(), regs[3], buf.data(), needed);
            for (int i = 0; i < ret && i < (int)dst_size; i++) mem.Write16(dst_addr + i*2, buf[i]);
            regs[0] = ret;
        } else regs[0] = needed;
        return true;
    });
    Thunk("WideCharToMultiByte", 197, [this](uint32_t* regs, EmulatedMemory& mem) -> bool {
        std::wstring src = ReadWStringFromEmu(mem, regs[2]);
        uint32_t dst_addr = ReadStackArg(regs, mem, 0);
        uint32_t dst_size = ReadStackArg(regs, mem, 1);
        int needed = WideCharToMultiByte(regs[0], regs[1], src.c_str(), regs[3], NULL, 0, NULL, NULL);
        if (dst_addr != 0 && dst_size > 0) {
            std::vector<char> buf(needed + 1);
            int ret = WideCharToMultiByte(regs[0], regs[1], src.c_str(), regs[3], buf.data(), needed, NULL, NULL);
            for (int i = 0; i < ret && i < (int)dst_size; i++) mem.Write8(dst_addr + i, buf[i]);
            regs[0] = ret;
        } else regs[0] = needed;
        return true;
    });
    Thunk("FormatMessageW", 234, [](uint32_t* regs, EmulatedMemory&) -> bool { regs[0] = 0; return true; });
    Thunk("CompareStringW", 198, [this](uint32_t* regs, EmulatedMemory& mem) -> bool {
        std::wstring s1, s2;
        if (regs[2]) s1 = ReadWStringFromEmu(mem, regs[2]);
        if (ReadStackArg(regs, mem, 0)) s2 = ReadWStringFromEmu(mem, ReadStackArg(regs, mem, 0));
        int32_t len1 = (int32_t)regs[3], len2 = (int32_t)ReadStackArg(regs, mem, 1);
        if (len1 >= 0 && (uint32_t)len1 < s1.size()) s1.resize(len1);
        if (len2 >= 0 && (uint32_t)len2 < s2.size()) s2.resize(len2);
        uint32_t flags = regs[1];
        int cmp;
        if (flags & NORM_IGNORECASE) cmp = _wcsicmp(s1.c_str(), s2.c_str());
        else cmp = wcscmp(s1.c_str(), s2.c_str());
        if (cmp < 0) regs[0] = 1; /* CSTR_LESS_THAN */
        else if (cmp == 0) regs[0] = 2; /* CSTR_EQUAL */
        else regs[0] = 3; /* CSTR_GREATER_THAN */
        return true;
    });
    Thunk("GetStringTypeW", 216, [](uint32_t* regs, EmulatedMemory&) -> bool { regs[0] = 0; return true; });
    Thunk("CharLowerW", 221, [](uint32_t* regs, EmulatedMemory&) -> bool {
        if (regs[0] < 0x10000) regs[0] = (uint32_t)towlower((wint_t)regs[0]);
        return true;
    });
    Thunk("CharUpperW", 224, [](uint32_t* regs, EmulatedMemory&) -> bool {
        if (regs[0] < 0x10000) regs[0] = (uint32_t)towupper((wint_t)regs[0]);
        return true;
    });
    Thunk("CharPrevW", 225, [](uint32_t* regs, EmulatedMemory&) -> bool {
        uint32_t start = regs[0], cur = regs[1];
        if (cur > start) regs[0] = cur - 2;
        else regs[0] = start;
        return true;
    });
    Thunk("CharNextW", 226, [this](uint32_t* regs, EmulatedMemory& mem) -> bool {
        if (mem.Read16(regs[0]) != 0) regs[0] += 2;
        return true;
    });
    Thunk("lstrcmpW", 227, [this](uint32_t* regs, EmulatedMemory& mem) -> bool {
        std::wstring a = ReadWStringFromEmu(mem, regs[0]), b = ReadWStringFromEmu(mem, regs[1]);
        regs[0] = (uint32_t)(int32_t)wcscmp(a.c_str(), b.c_str()); return true;
    });
    Thunk("lstrcmpiW", 228, [this](uint32_t* regs, EmulatedMemory& mem) -> bool {
        std::wstring a = ReadWStringFromEmu(mem, regs[0]), b = ReadWStringFromEmu(mem, regs[1]);
        regs[0] = (uint32_t)(int32_t)_wcsicmp(a.c_str(), b.c_str()); return true;
    });
    Thunk("_wcsnicmp", 229, [this](uint32_t* regs, EmulatedMemory& mem) -> bool {
        std::wstring a = ReadWStringFromEmu(mem, regs[0]), b = ReadWStringFromEmu(mem, regs[1]);
        regs[0] = (uint32_t)(int32_t)_wcsnicmp(a.c_str(), b.c_str(), regs[2]); return true;
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
        uint32_t dst = regs[0], src_ptr = regs[1], count = regs[2];
        std::wstring src = ReadWStringFromEmu(mem, src_ptr);
        uint32_t i;
        for (i = 0; i < count && i < (uint32_t)src.size(); i++)
            mem.Write8(dst + i, (uint8_t)src[i]);
        if (i < count) mem.Write8(dst + i, 0);
        regs[0] = i;
        return true;
    });
    Thunk("mbstowcs", 76, [this](uint32_t* regs, EmulatedMemory& mem) -> bool {
        uint32_t dst = regs[0], src_ptr = regs[1], count = regs[2];
        std::string src = ReadStringFromEmu(mem, src_ptr);
        uint32_t i;
        for (i = 0; i < count && i < (uint32_t)src.size(); i++)
            mem.Write16(dst + i * 2, (uint16_t)(uint8_t)src[i]);
        if (i < count) mem.Write16(dst + i * 2, 0);
        regs[0] = i;
        return true;
    });
    Thunk("wcstok", 77, [this](uint32_t* regs, EmulatedMemory& mem) -> bool {
        uint32_t str_addr = regs[0], delim_addr = regs[1];
        /* WinCE wcstok uses a static context (no third param like C11 wcstok_s).
           We implement it by reading the string, tokenizing, and writing back. */
        static thread_local uint32_t tok_addr = 0;
        static thread_local uint32_t tok_pos = 0;
        if (str_addr != 0) { tok_addr = str_addr; tok_pos = 0; }
        if (tok_addr == 0) { regs[0] = 0; return true; }
        std::wstring delim = ReadWStringFromEmu(mem, delim_addr);
        /* Skip leading delimiters */
        uint32_t cur = tok_addr + tok_pos * 2;
        while (true) {
            uint16_t ch = mem.Read16(cur);
            if (ch == 0) { regs[0] = 0; tok_addr = 0; return true; }
            bool is_delim = false;
            for (wchar_t d : delim) if (ch == d) { is_delim = true; break; }
            if (!is_delim) break;
            cur += 2; tok_pos++;
        }
        uint32_t token_start = cur;
        /* Find end of token */
        while (true) {
            uint16_t ch = mem.Read16(cur);
            if (ch == 0) { tok_addr = 0; break; }
            bool is_delim = false;
            for (wchar_t d : delim) if (ch == d) { is_delim = true; break; }
            if (is_delim) { mem.Write16(cur, 0); tok_pos = (cur - tok_addr) / 2 + 1; break; }
            cur += 2;
        }
        regs[0] = token_start;
        return true;
    });
    Thunk("wcspbrk", [this](uint32_t* regs, EmulatedMemory& mem) -> bool {
        std::wstring str = ReadWStringFromEmu(mem, regs[0]);
        std::wstring accept = ReadWStringFromEmu(mem, regs[1]);
        for (size_t i = 0; i < str.size(); i++) {
            for (wchar_t a : accept) {
                if (str[i] == a) {
                    regs[0] = regs[0] + (uint32_t)i * 2;
                    return true;
                }
            }
        }
        regs[0] = 0;
        return true;
    });
    ThunkOrdinal("wcspbrk", 68);
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
}
