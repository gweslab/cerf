/* Win32 thunks: memory allocation, string operations, math, C runtime */
#define NOMINMAX
#define _CRT_SECURE_NO_WARNINGS
#include "win32_thunks.h"
#include <cstdio>
#include <algorithm>

bool Win32Thunks::ExecuteMemoryThunk(const std::string& func, uint32_t* regs, EmulatedMemory& mem) {
    /* Memory management */
    if (func == "VirtualAlloc") {
        uint32_t addr_arg = regs[0];
        uint32_t size = regs[1];
        uint32_t allocType = regs[2];
        uint32_t protect = regs[3];
        static uint32_t next_valloc = 0x20000000;
        uint32_t base = (addr_arg != 0) ? addr_arg : next_valloc;
        uint8_t* ptr = mem.Alloc(base, size, protect);
        if (ptr) {
            if (addr_arg == 0) next_valloc = base + ((size + 0xFFF) & ~0xFFF);
            regs[0] = base;
        } else {
            regs[0] = 0;
        }
        printf("[THUNK] VirtualAlloc(0x%08X, 0x%X) -> 0x%08X\n", addr_arg, size, regs[0]);
        return true;
    }
    if (func == "VirtualFree") {
        regs[0] = 1;
        return true;
    }

    if (func == "LocalAlloc") {
        uint32_t flags = regs[0];
        uint32_t size = regs[1];
        static uint32_t next_local = 0x30000000;
        uint8_t* ptr = mem.Alloc(next_local, size);
        if (ptr) {
            if (flags & 0x40) memset(ptr, 0, size); /* LMEM_ZEROINIT */
            regs[0] = next_local;
            next_local += (size + 0xFFF) & ~0xFFF;
        } else {
            regs[0] = 0;
        }
        return true;
    }
    if (func == "LocalFree" || func == "LocalReAlloc") {
        regs[0] = 0;
        return true;
    }
    if (func == "LocalSize") {
        regs[0] = 0x1000;
        return true;
    }

    if (func == "GetProcessHeap") {
        regs[0] = 0xDEAD0001;
        return true;
    }
    if (func == "HeapAlloc" || func == "HeapCreate") {
        uint32_t size_arg = (func == "HeapAlloc") ? regs[2] : regs[1];
        static uint32_t next_heap = 0x40000000;
        mem.Alloc(next_heap, size_arg);
        regs[0] = next_heap;
        next_heap += (size_arg + 0xFFF) & ~0xFFF;
        return true;
    }
    if (func == "HeapFree" || func == "HeapDestroy") {
        regs[0] = 1;
        return true;
    }
    if (func == "HeapReAlloc") {
        uint32_t old_ptr = regs[2];
        uint32_t new_size = regs[3];
        static uint32_t next_hrealloc = 0x41000000;
        uint8_t* old_host = mem.Translate(old_ptr);
        uint8_t* new_host = mem.Alloc(next_hrealloc, new_size);
        if (old_host && new_host) memcpy(new_host, old_host, new_size);
        regs[0] = next_hrealloc;
        next_hrealloc += (new_size + 0xFFF) & ~0xFFF;
        return true;
    }
    if (func == "HeapSize") {
        regs[0] = 0x1000;
        return true;
    }
    if (func == "HeapValidate") {
        regs[0] = 1;
        return true;
    }

    if (func == "malloc" || func == "calloc" || func == "new" || func == "realloc") {
        uint32_t size = (func == "calloc") ? regs[0] * regs[1] : regs[0];
        if (func == "realloc") size = regs[1];
        static uint32_t next_malloc = 0x42000000;
        mem.Alloc(next_malloc, size > 0 ? size : 0x10);
        if (func == "calloc") {
            uint8_t* p = mem.Translate(next_malloc);
            if (p) memset(p, 0, size);
        }
        regs[0] = next_malloc;
        next_malloc += ((size > 0 ? size : 0x10) + 0xFFF) & ~0xFFF;
        return true;
    }
    if (func == "free" || func == "delete") {
        regs[0] = 0;
        return true;
    }
    if (func == "_msize") {
        regs[0] = 0x1000;
        return true;
    }

    /* Memory functions */
    if (func == "memcpy" || func == "memmove") {
        uint32_t dst = regs[0], src = regs[1], len = regs[2];
        uint8_t* dst_p = mem.Translate(dst);
        uint8_t* src_p = mem.Translate(src);
        if (dst_p && src_p) {
            if (func == "memmove") memmove(dst_p, src_p, len);
            else memcpy(dst_p, src_p, len);
        }
        regs[0] = dst;
        return true;
    }
    if (func == "memset") {
        uint32_t dst = regs[0];
        uint8_t val = (uint8_t)regs[1];
        uint32_t len = regs[2];
        uint8_t* p = mem.Translate(dst);
        if (p) memset(p, val, len);
        regs[0] = dst;
        return true;
    }
    if (func == "memcmp" || func == "_memicmp") {
        uint32_t a = regs[0], b = regs[1], len = regs[2];
        uint8_t* ap = mem.Translate(a);
        uint8_t* bp = mem.Translate(b);
        if (ap && bp) {
            if (func == "_memicmp") regs[0] = (uint32_t)_memicmp(ap, bp, len);
            else regs[0] = (uint32_t)memcmp(ap, bp, len);
        } else regs[0] = 0;
        return true;
    }

    /* Math functions */
    if (func == "qsort") {
        printf("[THUNK] WARNING: qsort called - stubbed\n");
        return true;
    }
    if (func == "rand") {
        regs[0] = (uint32_t)rand();
        return true;
    }
    if (func == "Random") {
        regs[0] = (uint32_t)(rand() % 0xFFFF);
        return true;
    }

    return false;
}

bool Win32Thunks::ExecuteStringThunk(const std::string& func, uint32_t* regs, EmulatedMemory& mem) {
    if (func == "wsprintfW") {
        uint32_t dst_addr = regs[0];
        std::wstring fmt = ReadWStringFromEmu(mem, regs[1]);
        uint32_t args[10];
        args[0] = regs[2];
        args[1] = regs[3];
        for (int i = 2; i < 10; i++) args[i] = ReadStackArg(regs, mem, i - 2);

        std::wstring result;
        int arg_idx = 0;
        for (size_t i = 0; i < fmt.size(); i++) {
            if (fmt[i] == L'%' && i + 1 < fmt.size()) {
                i++;
                while (i < fmt.size() && (fmt[i] >= L'0' && fmt[i] <= L'9')) i++;
                if (i >= fmt.size()) break;
                if (fmt[i] == L'd' || fmt[i] == L'i') {
                    result += std::to_wstring((int)args[arg_idx++]);
                } else if (fmt[i] == L'u') {
                    result += std::to_wstring(args[arg_idx++]);
                } else if (fmt[i] == L'x' || fmt[i] == L'X') {
                    wchar_t buf[16]; wsprintfW(buf, L"%x", args[arg_idx++]);
                    result += buf;
                } else if (fmt[i] == L's') {
                    result += ReadWStringFromEmu(mem, args[arg_idx++]);
                } else if (fmt[i] == L'%') {
                    result += L'%';
                } else {
                    result += L'?';
                    arg_idx++;
                }
            } else {
                result += fmt[i];
            }
        }
        for (size_t i = 0; i < result.size(); i++) {
            mem.Write16(dst_addr + (uint32_t)i * 2, result[i]);
        }
        mem.Write16(dst_addr + (uint32_t)result.size() * 2, 0);
        regs[0] = (uint32_t)result.size();
        return true;
    }
    if (func == "wcslen") {
        uint32_t str_addr = regs[0];
        uint32_t len = 0;
        while (mem.Read16(str_addr + len * 2) != 0) len++;
        regs[0] = len;
        return true;
    }
    if (func == "wcscpy") {
        uint32_t dst = regs[0], src = regs[1];
        uint32_t i = 0;
        uint16_t ch;
        do {
            ch = mem.Read16(src + i * 2);
            mem.Write16(dst + i * 2, ch);
            i++;
        } while (ch != 0);
        regs[0] = dst;
        return true;
    }
    if (func == "wcscat") {
        uint32_t dst = regs[0], src = regs[1];
        uint32_t dlen = 0;
        while (mem.Read16(dst + dlen * 2) != 0) dlen++;
        uint32_t i = 0;
        uint16_t ch;
        do {
            ch = mem.Read16(src + i * 2);
            mem.Write16(dst + (dlen + i) * 2, ch);
            i++;
        } while (ch != 0);
        regs[0] = dst;
        return true;
    }
    if (func == "wcscmp") {
        std::wstring s1 = ReadWStringFromEmu(mem, regs[0]);
        std::wstring s2 = ReadWStringFromEmu(mem, regs[1]);
        regs[0] = (uint32_t)wcscmp(s1.c_str(), s2.c_str());
        return true;
    }
    if (func == "wcsncpy") {
        uint32_t dst = regs[0], src = regs[1], count = regs[2];
        for (uint32_t i = 0; i < count; i++) {
            uint16_t ch = mem.Read16(src + i * 2);
            mem.Write16(dst + i * 2, ch);
            if (ch == 0) {
                for (uint32_t j = i + 1; j < count; j++)
                    mem.Write16(dst + j * 2, 0);
                break;
            }
        }
        regs[0] = dst;
        return true;
    }
    if (func == "wcsncmp") {
        std::wstring s1 = ReadWStringFromEmu(mem, regs[0]);
        std::wstring s2 = ReadWStringFromEmu(mem, regs[1]);
        regs[0] = (uint32_t)wcsncmp(s1.c_str(), s2.c_str(), regs[2]);
        return true;
    }
    if (func == "_wcsicmp") {
        std::wstring s1 = ReadWStringFromEmu(mem, regs[0]);
        std::wstring s2 = ReadWStringFromEmu(mem, regs[1]);
        regs[0] = (uint32_t)_wcsicmp(s1.c_str(), s2.c_str());
        return true;
    }
    if (func == "wcschr") {
        uint32_t str = regs[0];
        uint16_t ch = (uint16_t)regs[1];
        while (true) {
            uint16_t c = mem.Read16(str);
            if (c == ch) { regs[0] = str; return true; }
            if (c == 0) { regs[0] = 0; return true; }
            str += 2;
        }
    }
    if (func == "wcsrchr") {
        uint32_t str = regs[0];
        uint16_t ch = (uint16_t)regs[1];
        uint32_t last = 0;
        while (true) {
            uint16_t c = mem.Read16(str);
            if (c == ch) last = str;
            if (c == 0) break;
            str += 2;
        }
        regs[0] = last;
        return true;
    }
    if (func == "wcsstr") {
        std::wstring s1 = ReadWStringFromEmu(mem, regs[0]);
        std::wstring s2 = ReadWStringFromEmu(mem, regs[1]);
        auto pos = s1.find(s2);
        regs[0] = (pos != std::wstring::npos) ? regs[0] + (uint32_t)(pos * 2) : 0;
        return true;
    }
    if (func == "_wtol") {
        std::wstring s = ReadWStringFromEmu(mem, regs[0]);
        regs[0] = (uint32_t)_wtol(s.c_str());
        return true;
    }
    if (func == "wcstol") {
        std::wstring s = ReadWStringFromEmu(mem, regs[0]);
        regs[0] = (uint32_t)wcstol(s.c_str(), NULL, regs[2]);
        return true;
    }
    if (func == "towlower") {
        regs[0] = (uint32_t)towlower((wint_t)regs[0]);
        return true;
    }
    if (func == "towupper") {
        regs[0] = (uint32_t)towupper((wint_t)regs[0]);
        return true;
    }
    if (func == "iswctype") {
        regs[0] = (uint32_t)iswctype((wint_t)regs[0], regs[1]);
        return true;
    }

    /* Locale / codepage string functions */
    if (func == "MultiByteToWideChar") {
        std::string src = ReadStringFromEmu(mem, regs[2]);
        int needed = MultiByteToWideChar(regs[0], regs[1], src.c_str(), regs[3], NULL, 0);
        if (regs[4] != 0 && regs[5] > 0) {
            std::vector<wchar_t> buf(needed + 1);
            int ret = MultiByteToWideChar(regs[0], regs[1], src.c_str(), regs[3], buf.data(), needed);
            for (int i = 0; i < ret && i < (int)regs[5]; i++)
                mem.Write16(regs[4] + i * 2, buf[i]);
            regs[0] = ret;
        } else {
            regs[0] = needed;
        }
        return true;
    }
    if (func == "WideCharToMultiByte") {
        std::wstring src = ReadWStringFromEmu(mem, regs[2]);
        int needed = WideCharToMultiByte(regs[0], regs[1], src.c_str(), regs[3], NULL, 0, NULL, NULL);
        uint32_t dst_addr = ReadStackArg(regs, mem, 0);
        uint32_t dst_size = ReadStackArg(regs, mem, 1);
        if (dst_addr != 0 && dst_size > 0) {
            std::vector<char> buf(needed + 1);
            int ret = WideCharToMultiByte(regs[0], regs[1], src.c_str(), regs[3], buf.data(), needed, NULL, NULL);
            for (int i = 0; i < ret && i < (int)dst_size; i++)
                mem.Write8(dst_addr + i, buf[i]);
            regs[0] = ret;
        } else {
            regs[0] = needed;
        }
        return true;
    }
    if (func == "FormatMessageW") {
        /* Stub - return 0 */
        regs[0] = 0;
        return true;
    }
    if (func == "CompareStringW") {
        regs[0] = CSTR_EQUAL;
        return true;
    }
    if (func == "GetStringTypeW") {
        regs[0] = 0;
        return true;
    }
    if (func == "CharLowerW" || func == "CharUpperW") {
        /* If HIWORD is 0, it's a single character */
        if ((regs[0] & 0xFFFF0000) == 0) {
            regs[0] = (func == "CharLowerW") ? (uint32_t)towlower(regs[0]) : (uint32_t)towupper(regs[0]);
        }
        return true;
    }
    if (func == "CharNextW") {
        if (regs[0] && mem.Read16(regs[0]) != 0) {
            regs[0] += 2;
        }
        return true;
    }
    if (func == "lstrcmpW") {
        std::wstring s1 = ReadWStringFromEmu(mem, regs[0]);
        std::wstring s2 = ReadWStringFromEmu(mem, regs[1]);
        regs[0] = (uint32_t)lstrcmpW(s1.c_str(), s2.c_str());
        return true;
    }
    if (func == "lstrcmpiW") {
        std::wstring s1 = ReadWStringFromEmu(mem, regs[0]);
        std::wstring s2 = ReadWStringFromEmu(mem, regs[1]);
        regs[0] = (uint32_t)lstrcmpiW(s1.c_str(), s2.c_str());
        return true;
    }
    if (func == "_wcsnicmp") {
        std::wstring s1 = ReadWStringFromEmu(mem, regs[0]);
        std::wstring s2 = ReadWStringFromEmu(mem, regs[1]);
        regs[0] = (uint32_t)_wcsnicmp(s1.c_str(), s2.c_str(), regs[2]);
        return true;
    }
    if (func == "_wcsdup") {
        /* Allocate copy in emulated memory */
        std::wstring s = ReadWStringFromEmu(mem, regs[0]);
        static uint32_t next_dup = 0x43000000;
        uint32_t sz = ((uint32_t)s.size() + 1) * 2;
        mem.Alloc(next_dup, sz);
        for (size_t i = 0; i <= s.size(); i++)
            mem.Write16(next_dup + (uint32_t)i * 2, s[i]);
        regs[0] = next_dup;
        next_dup += (sz + 0xFFF) & ~0xFFF;
        return true;
    }
    if (func == "wcstombs") {
        std::wstring src = ReadWStringFromEmu(mem, regs[1]);
        uint32_t dst = regs[0];
        uint32_t count = regs[2];
        for (uint32_t i = 0; i < count && i < (uint32_t)src.size(); i++)
            mem.Write8(dst + i, (uint8_t)src[i]);
        if (count > 0) mem.Write8(dst + std::min(count - 1, (uint32_t)src.size()), 0);
        regs[0] = (uint32_t)src.size();
        return true;
    }
    if (func == "mbstowcs") {
        std::string src = ReadStringFromEmu(mem, regs[1]);
        uint32_t dst = regs[0];
        uint32_t count = regs[2];
        for (uint32_t i = 0; i < count && i < (uint32_t)src.size(); i++)
            mem.Write16(dst + i * 2, (uint16_t)(uint8_t)src[i]);
        if (count > 0) mem.Write16(dst + std::min(count - 1, (uint32_t)src.size()) * 2, 0);
        regs[0] = (uint32_t)src.size();
        return true;
    }
    if (func == "wcstok" || func == "wcspbrk") {
        /* Stub */
        regs[0] = 0;
        return true;
    }
    if (func == "_snwprintf" || func == "swprintf" || func == "swscanf" || func == "wvsprintfW") {
        /* Basic stub */
        regs[0] = 0;
        return true;
    }

    return false;
}
