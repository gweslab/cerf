/* CRT thunks: memcpy, memset, qsort, rand, math */
#include "../win32_thunks.h"
#include "../../log.h"
#include <cstdio>
#include <cstring>
#include <cmath>

void Win32Thunks::RegisterCrtHandlers() {
    Thunk("memcpy", 1044, [this](uint32_t* regs, EmulatedMemory& mem) -> bool {
        uint32_t dst = regs[0], src = regs[1], len = regs[2];
        if (len > 0x100000) {
            LOG(API, "[API] memcpy(0x%08X, 0x%08X, 0x%X) -> HUGE len, capping\n", dst, src, len);
            len = 0x100000;
        }
        uint8_t* dst_p = mem.Translate(dst);
        uint8_t* src_p = mem.Translate(src);
        if (dst_p && src_p && len > 0) {
            /* Verify host pointers are contiguous (same region) for both src and dst.
               Fallback regions are NOT identity-mapped, so two adjacent emulated pages
               may have non-adjacent host addresses. Native memcpy would overrun. */
            uint8_t* dst_end = mem.Translate(dst + len - 1);
            uint8_t* src_end = mem.Translate(src + len - 1);
            bool dst_contiguous = dst_end && (dst_end == dst_p + len - 1);
            bool src_contiguous = src_end && (src_end == src_p + len - 1);
            if (dst_contiguous && src_contiguous) {
                memcpy(dst_p, src_p, len);
            } else {
                /* Cross-region copy: do byte-by-byte via emulated memory */
                for (uint32_t i = 0; i < len; i++)
                    mem.Write8(dst + i, mem.Read8(src + i));
            }
        }
        regs[0] = dst; return true;
    });
    Thunk("memmove", 1046, [this](uint32_t* regs, EmulatedMemory& mem) -> bool {
        uint32_t dst = regs[0], src = regs[1], len = regs[2];
        uint8_t* dst_p = mem.Translate(dst);
        uint8_t* src_p = mem.Translate(src);
        if (dst_p && src_p && len > 0) {
            uint8_t* dst_end = mem.Translate(dst + len - 1);
            uint8_t* src_end = mem.Translate(src + len - 1);
            bool dst_ok = dst_end && (dst_end == dst_p + len - 1);
            bool src_ok = src_end && (src_end == src_p + len - 1);
            if (dst_ok && src_ok) {
                memmove(dst_p, src_p, len);
            } else {
                if (dst <= src) {
                    for (uint32_t i = 0; i < len; i++)
                        mem.Write8(dst + i, mem.Read8(src + i));
                } else {
                    for (uint32_t i = len; i > 0; i--)
                        mem.Write8(dst + i - 1, mem.Read8(src + i - 1));
                }
            }
        }
        regs[0] = dst; return true;
    });
    Thunk("memset", 1047, [this](uint32_t* regs, EmulatedMemory& mem) -> bool {
        uint32_t dst = regs[0], val = regs[1] & 0xFF, len = regs[2];
        uint8_t* p = mem.Translate(dst);
        if (p && len > 0) {
            uint8_t* p_end = mem.Translate(dst + len - 1);
            if (p_end && (p_end == p + len - 1)) {
                memset(p, val, len);
            } else {
                for (uint32_t i = 0; i < len; i++)
                    mem.Write8(dst + i, (uint8_t)val);
            }
        }
        regs[0] = dst; return true;
    });
    Thunk("memcmp", 1043, [this](uint32_t* regs, EmulatedMemory& mem) -> bool {
        uint8_t* ap = mem.Translate(regs[0]);
        uint8_t* bp = mem.Translate(regs[1]);
        regs[0] = (ap && bp) ? (uint32_t)memcmp(ap, bp, regs[2]) : 0;
        return true;
    });
    Thunk("_memicmp", [this](uint32_t* regs, EmulatedMemory& mem) -> bool {
        uint8_t* ap = mem.Translate(regs[0]);
        uint8_t* bp = mem.Translate(regs[1]);
        regs[0] = (ap && bp) ? (uint32_t)_memicmp(ap, bp, regs[2]) : 0;
        return true;
    });
    Thunk("qsort", 1052, [](uint32_t* regs, EmulatedMemory&) -> bool {
        LOG(API, "[API] WARNING: qsort called - stubbed\n"); return true;
    });
    Thunk("rand", 1053, [](uint32_t* regs, EmulatedMemory&) -> bool {
        regs[0] = (uint32_t)rand(); return true;
    });
    Thunk("Random", 80, [](uint32_t* regs, EmulatedMemory&) -> bool {
        regs[0] = (uint32_t)(rand() % 0xFFFF); return true;
    });
    Thunk("srand", 1061, [](uint32_t* regs, EmulatedMemory&) -> bool {
        srand(regs[0]); return true;
    });
    Thunk("pow", 1051, [](uint32_t* regs, EmulatedMemory&) -> bool {
        uint64_t ba = ((uint64_t)regs[1] << 32) | regs[0];
        uint64_t bb = ((uint64_t)regs[3] << 32) | regs[2];
        double a, b; memcpy(&a, &ba, 8); memcpy(&b, &bb, 8);
        double r = pow(a, b); uint64_t rb; memcpy(&rb, &r, 8);
        regs[0] = (uint32_t)rb; regs[1] = (uint32_t)(rb >> 32);
        return true;
    });
    Thunk("sqrt", 1060, [](uint32_t* regs, EmulatedMemory&) -> bool {
        uint64_t bits = ((uint64_t)regs[1] << 32) | regs[0];
        double d; memcpy(&d, &bits, 8); d = sqrt(d); memcpy(&bits, &d, 8);
        regs[0] = (uint32_t)bits; regs[1] = (uint32_t)(bits >> 32);
        return true;
    });
    Thunk("floor", 1013, [](uint32_t* regs, EmulatedMemory&) -> bool {
        uint64_t bits = ((uint64_t)regs[1] << 32) | regs[0];
        double d; memcpy(&d, &bits, 8); d = floor(d); memcpy(&bits, &d, 8);
        regs[0] = (uint32_t)bits; regs[1] = (uint32_t)(bits >> 32);
        return true;
    });
    Thunk("strncpy", 1071, [this](uint32_t* regs, EmulatedMemory& mem) -> bool {
        uint32_t dst = regs[0], src = regs[1], count = regs[2];
        uint8_t* dst_p = mem.Translate(dst);
        uint8_t* src_p = mem.Translate(src);
        if (dst_p && src_p) strncpy((char*)dst_p, (char*)src_p, count);
        regs[0] = dst;
        return true;
    });
    Thunk("_wfopen", 1145, [this](uint32_t* regs, EmulatedMemory& mem) -> bool {
        std::wstring filename = ReadWStringFromEmu(mem, regs[0]);
        std::wstring mode = ReadWStringFromEmu(mem, regs[1]);
        /* WinCE doesn't distinguish text/binary modes — force binary */
        std::wstring native_mode = mode;
        if (native_mode.find(L'b') == std::wstring::npos && native_mode.find(L't') == std::wstring::npos)
            native_mode += L'b';
        std::wstring host_path = MapWinCEPath(filename);
        LOG(API, "[API] _wfopen('%ls' -> '%ls', '%ls')\n", filename.c_str(), host_path.c_str(), mode.c_str());
        FILE* f = _wfopen(host_path.c_str(), native_mode.c_str());
        regs[0] = f ? WrapHandle(f) : 0;
        return true;
    });
    Thunk("fclose", 1118, [this](uint32_t* regs, EmulatedMemory&) -> bool {
        if (!regs[0]) { regs[0] = (uint32_t)-1; return true; }
        FILE* f = (FILE*)UnwrapHandle(regs[0]);
        RemoveHandle(regs[0]);
        regs[0] = f ? (uint32_t)fclose(f) : (uint32_t)-1;
        return true;
    });
    Thunk("fgetws", 1143, [this](uint32_t* regs, EmulatedMemory& mem) -> bool {
        uint32_t buf_addr = regs[0];
        int count = (int)regs[1];
        FILE* f = (FILE*)UnwrapHandle(regs[2]);
        if (!f || count <= 0) { regs[0] = 0; return true; }
        std::vector<wchar_t> buf(count);
        wchar_t* result = fgetws(buf.data(), count, f);
        if (result) {
            for (int i = 0; i < count; i++) {
                mem.Write16(buf_addr + i * 2, buf[i]);
                if (buf[i] == 0) break;
            }
            regs[0] = buf_addr;
        } else {
            regs[0] = 0;
        }
        return true;
    });
    Thunk("abs", 988, [](uint32_t* regs, EmulatedMemory&) -> bool {
        regs[0] = (uint32_t)abs((int)regs[0]);
        return true;
    });

    /* ---- Math functions: double f(double) ---- */
    /* ARM calling convention: double in r0:r1 (lo:hi), result in r0:r1 */
    #define MATH_UNARY(name, ord, fn) \
        Thunk(name, ord, [](uint32_t* regs, EmulatedMemory&) -> bool { \
            uint64_t bits = ((uint64_t)regs[1] << 32) | regs[0]; \
            double d; memcpy(&d, &bits, 8); d = fn(d); memcpy(&bits, &d, 8); \
            regs[0] = (uint32_t)bits; regs[1] = (uint32_t)(bits >> 32); \
            return true; \
        })
    MATH_UNARY("acos", 989, acos);
    MATH_UNARY("asin", 990, asin);
    MATH_UNARY("atan", 991, atan);
    MATH_UNARY("cos", 1004, cos);
    MATH_UNARY("cosh", 1005, cosh);
    MATH_UNARY("exp", 1009, exp);
    MATH_UNARY("log", 1033, log);
    MATH_UNARY("log10", 1034, log10);
    MATH_UNARY("sin", 1058, sin);
    MATH_UNARY("sinh", 1059, sinh);
    MATH_UNARY("tan", 1075, tan);
    MATH_UNARY("tanh", 1076, tanh);
    MATH_UNARY("ceil", 999, ceil);
    #undef MATH_UNARY

    /* fmod(double x, double y) -> double: two double args in r0:r1, r2:r3 */
    Thunk("fmod", 1014, [](uint32_t* regs, EmulatedMemory&) -> bool {
        uint64_t ba = ((uint64_t)regs[1] << 32) | regs[0];
        uint64_t bb = ((uint64_t)regs[3] << 32) | regs[2];
        double a, b; memcpy(&a, &ba, 8); memcpy(&b, &bb, 8);
        double r = fmod(a, b); uint64_t rb; memcpy(&rb, &r, 8);
        regs[0] = (uint32_t)rb; regs[1] = (uint32_t)(rb >> 32);
        return true;
    });
    /* atan2(double y, double x) -> double */
    Thunk("atan2", 992, [](uint32_t* regs, EmulatedMemory&) -> bool {
        uint64_t ba = ((uint64_t)regs[1] << 32) | regs[0];
        uint64_t bb = ((uint64_t)regs[3] << 32) | regs[2];
        double a, b; memcpy(&a, &ba, 8); memcpy(&b, &bb, 8);
        double r = atan2(a, b); uint64_t rb; memcpy(&rb, &r, 8);
        regs[0] = (uint32_t)rb; regs[1] = (uint32_t)(rb >> 32);
        return true;
    });
    /* modf(double x, double* iptr) -> double fractional part */
    Thunk("modf", 1048, [this](uint32_t* regs, EmulatedMemory& mem) -> bool {
        uint64_t bits = ((uint64_t)regs[1] << 32) | regs[0];
        double d; memcpy(&d, &bits, 8);
        double ipart;
        double frac = modf(d, &ipart);
        /* Write integer part to pointer in r2 */
        uint32_t iptr_addr = regs[2];
        if (iptr_addr) {
            uint64_t ibits; memcpy(&ibits, &ipart, 8);
            mem.Write32(iptr_addr, (uint32_t)ibits);
            mem.Write32(iptr_addr + 4, (uint32_t)(ibits >> 32));
        }
        uint64_t fb; memcpy(&fb, &frac, 8);
        regs[0] = (uint32_t)fb; regs[1] = (uint32_t)(fb >> 32);
        return true;
    });
    /* _gcvt(double value, int digits, char* buffer) -> char* buffer */
    Thunk("_gcvt", 1022, [this](uint32_t* regs, EmulatedMemory& mem) -> bool {
        uint64_t bits = ((uint64_t)regs[1] << 32) | regs[0];
        double d; memcpy(&d, &bits, 8);
        int digits = (int)regs[2];
        uint32_t buf_addr = regs[3];
        char buf[64];
        _gcvt(d, digits, buf);
        uint8_t* dst = mem.Translate(buf_addr);
        if (dst) strcpy((char*)dst, buf);
        regs[0] = buf_addr;
        return true;
    });
    Thunk("atof", 995, [this](uint32_t* regs, EmulatedMemory& mem) -> bool {
        const char* str = (const char*)mem.Translate(regs[0]);
        double result = str ? atof(str) : 0.0;
        uint64_t bits; memcpy(&bits, &result, 8);
        regs[0] = (uint32_t)bits; regs[1] = (uint32_t)(bits >> 32);
        LOG(API, "[API] atof('%s') -> %f\n", str ? str : "(null)", result);
        return true;
    });
    Thunk("atol", 994, [this](uint32_t* regs, EmulatedMemory& mem) -> bool {
        const char* str = (const char*)mem.Translate(regs[0]);
        regs[0] = str ? (uint32_t)atol(str) : 0;
        return true;
    });

    Thunk("strcat", 1063, [this](uint32_t* regs, EmulatedMemory& mem) -> bool {
        uint32_t dst = regs[0], src = regs[1];
        uint8_t* dst_p = mem.Translate(dst);
        uint8_t* src_p = mem.Translate(src);
        if (dst_p && src_p) {
            size_t dlen = strlen((char*)dst_p);
            size_t slen = strlen((char*)src_p);
            /* Byte-by-byte for safety across region boundaries */
            for (size_t i = 0; i <= slen; i++)
                mem.Write8(dst + (uint32_t)(dlen + i), mem.Read8(src + (uint32_t)i));
        }
        regs[0] = dst;
        return true;
    });

    Thunk("strtok", 1073, [this](uint32_t* regs, EmulatedMemory& mem) -> bool {
        /* strtok(str, delimiters) — uses static state */
        static uint32_t saved_ptr = 0;
        uint32_t str = regs[0] ? regs[0] : saved_ptr;
        if (!str) { regs[0] = 0; return true; }
        std::string delims = ReadStringFromEmu(mem, regs[1]);
        /* Skip leading delimiters */
        while (mem.Read8(str) && delims.find((char)mem.Read8(str)) != std::string::npos) str++;
        if (!mem.Read8(str)) { saved_ptr = 0; regs[0] = 0; return true; }
        uint32_t token_start = str;
        /* Find end of token */
        while (mem.Read8(str) && delims.find((char)mem.Read8(str)) == std::string::npos) str++;
        if (mem.Read8(str)) {
            mem.Write8(str, 0); /* null-terminate */
            saved_ptr = str + 1;
        } else {
            saved_ptr = 0;
        }
        regs[0] = token_start;
        return true;
    });

    Thunk("wcstod", 1081, [this](uint32_t* regs, EmulatedMemory& mem) -> bool {
        std::wstring s = ReadWStringFromEmu(mem, regs[0]);
        wchar_t* end = nullptr;
        double result = wcstod(s.c_str(), &end);
        uint32_t endptr_addr = regs[1];
        if (endptr_addr) {
            uint32_t consumed = end ? (uint32_t)(end - s.c_str()) : 0;
            mem.Write32(endptr_addr, regs[0] + consumed * 2);
        }
        uint64_t bits; memcpy(&bits, &result, 8);
        regs[0] = (uint32_t)bits; regs[1] = (uint32_t)(bits >> 32);
        return true;
    });

    Thunk("strtod", 1403, [this](uint32_t* regs, EmulatedMemory& mem) -> bool {
        const char* str = (const char*)mem.Translate(regs[0]);
        char* end = nullptr;
        double result = str ? strtod(str, &end) : 0.0;
        uint32_t endptr_addr = regs[1];
        if (endptr_addr && str) {
            uint32_t consumed = end ? (uint32_t)(end - str) : 0;
            mem.Write32(endptr_addr, regs[0] + consumed);
        }
        uint64_t bits; memcpy(&bits, &result, 8);
        regs[0] = (uint32_t)bits; regs[1] = (uint32_t)(bits >> 32);
        return true;
    });

    /* fopen(filename, mode) — narrow char version */
    Thunk("fopen", 1113, [this](uint32_t* regs, EmulatedMemory& mem) -> bool {
        std::string filename = ReadStringFromEmu(mem, regs[0]);
        std::string mode = ReadStringFromEmu(mem, regs[1]);
        /* WinCE doesn't distinguish text/binary modes, but Windows desktop does.
           Force binary mode to prevent CRLF translation corrupting binary files. */
        std::string native_mode = mode;
        if (native_mode.find('b') == std::string::npos && native_mode.find('t') == std::string::npos)
            native_mode += 'b';
        /* Convert narrow to wide for VFS path mapping */
        std::wstring wpath(filename.begin(), filename.end());
        std::wstring host_path = MapWinCEPath(wpath);
        LOG(API, "[API] fopen('%s' -> '%ls', '%s')\n", filename.c_str(), host_path.c_str(), mode.c_str());
        std::wstring wmode(native_mode.begin(), native_mode.end());
        FILE* f = _wfopen(host_path.c_str(), wmode.c_str());
        regs[0] = f ? WrapHandle(f) : 0;
        return true;
    });
}
