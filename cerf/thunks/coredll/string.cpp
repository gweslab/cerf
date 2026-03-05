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
                while (i < fmt.size() && (fmt[i] == L'-' || fmt[i] == L'+' || fmt[i] == L' ' || fmt[i] == L'0' || fmt[i] == L'#')) {
                    if (fmt[i] == L'-') left_align = true;
                    if (fmt[i] == L'0') zero_pad = true;
                    i++;
                }
                /* Collect width */
                int width = 0;
                while (i < fmt.size() && fmt[i] >= L'0' && fmt[i] <= L'9') {
                    width = width * 10 + (fmt[i] - L'0'); i++;
                }
                /* Precision */
                int precision = -1;
                if (i < fmt.size() && fmt[i] == L'.') {
                    i++; precision = 0;
                    while (i < fmt.size() && fmt[i] >= L'0' && fmt[i] <= L'9') {
                        precision = precision * 10 + (fmt[i] - L'0'); i++;
                    }
                }
                /* Length modifier: l, h, I64 */
                bool is_i64 = false;
                if (i + 2 < fmt.size() && fmt[i] == L'I' && fmt[i+1] == L'6' && fmt[i+2] == L'4') {
                    is_i64 = true; i += 3;
                } else if (i < fmt.size() && (fmt[i] == L'l' || fmt[i] == L'h')) {
                    i++;
                    if (i < fmt.size() && (fmt[i] == L'l' || fmt[i] == L'h')) i++;
                }
                if (i >= fmt.size()) break;
                if (arg_idx >= nargs) { result += L'?'; arg_idx++; continue; }
                wchar_t spec = fmt[i];
                /* Helper: apply width/padding to a formatted string */
                auto pad = [&](std::wstring s) {
                    while ((int)s.size() < width) {
                        if (left_align) s += L' ';
                        else s.insert(s.begin(), zero_pad ? L'0' : L' ');
                    }
                    result += s;
                };
                if (spec == L'd' || spec == L'i') {
                    wchar_t buf[32];
                    if (is_i64 && arg_idx + 1 < nargs) {
                        int64_t val = (int64_t)(((uint64_t)args[arg_idx+1] << 32) | args[arg_idx]);
                        arg_idx += 2;
                        _snwprintf_s(buf, _countof(buf), _TRUNCATE, L"%lld", val);
                    } else {
                        _snwprintf_s(buf, _countof(buf), _TRUNCATE, L"%d", (int)args[arg_idx++]);
                    }
                    pad(buf);
                } else if (spec == L'u') {
                    wchar_t buf[32];
                    if (is_i64 && arg_idx + 1 < nargs) {
                        uint64_t val = ((uint64_t)args[arg_idx+1] << 32) | args[arg_idx];
                        arg_idx += 2;
                        _snwprintf_s(buf, _countof(buf), _TRUNCATE, L"%llu", val);
                    } else {
                        _snwprintf_s(buf, _countof(buf), _TRUNCATE, L"%u", args[arg_idx++]);
                    }
                    pad(buf);
                } else if (spec == L'x') {
                    wchar_t buf[32]; _snwprintf_s(buf, _countof(buf), _TRUNCATE, L"%x", args[arg_idx++]);
                    pad(buf);
                } else if (spec == L'X') {
                    wchar_t buf[32]; _snwprintf_s(buf, _countof(buf), _TRUNCATE, L"%X", args[arg_idx++]);
                    pad(buf);
                } else if (spec == L'c') {
                    result += (wchar_t)args[arg_idx++];
                } else if (spec == L's') {
                    std::wstring s;
                    if (args[arg_idx]) s = ReadWStringFromEmu(mem, args[arg_idx]);
                    arg_idx++;
                    if (precision >= 0 && (int)s.size() > precision) s.resize(precision);
                    pad(s);
                } else if (spec == L'S') {
                    std::wstring s;
                    if (args[arg_idx]) {
                        std::string ns = ReadStringFromEmu(mem, args[arg_idx]);
                        for (char c : ns) s += (wchar_t)(unsigned char)c;
                    }
                    arg_idx++;
                    if (precision >= 0 && (int)s.size() > precision) s.resize(precision);
                    pad(s);
                } else if (spec == L'f' || spec == L'e' || spec == L'E' || spec == L'g' || spec == L'G') {
                    /* Floating-point: doubles occupy two consecutive 32-bit args on ARM */
                    if (arg_idx + 1 < nargs) {
                        uint64_t bits = ((uint64_t)args[arg_idx + 1] << 32) | args[arg_idx];
                        double val; memcpy(&val, &bits, 8);
                        arg_idx += 2;
                        wchar_t fmtbuf[16];
                        if (precision >= 0)
                            _snwprintf_s(fmtbuf, _countof(fmtbuf), _TRUNCATE, L"%%%d.%d%c", width, precision, (char)spec);
                        else if (width > 0)
                            _snwprintf_s(fmtbuf, _countof(fmtbuf), _TRUNCATE, L"%%%d%c", width, (char)spec);
                        else
                            _snwprintf_s(fmtbuf, _countof(fmtbuf), _TRUNCATE, L"%%%c", (char)spec);
                        wchar_t buf[64];
                        _snwprintf_s(buf, _countof(buf), _TRUNCATE, fmtbuf, val);
                        pad(buf);
                    } else { result += L'?'; arg_idx = nargs; }
                } else if (spec == L'p') {
                    wchar_t buf[32]; _snwprintf_s(buf, _countof(buf), _TRUNCATE, L"%08X", args[arg_idx++]);
                    result += buf;
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
        std::wstring s1 = ReadWStringFromEmu(mem,regs[0]), s2 = ReadWStringFromEmu(mem,regs[1]);
        regs[0] = (uint32_t)wcsncmp(s1.c_str(), s2.c_str(), regs[2]);
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
        std::wstring s = ReadWStringFromEmu(mem, regs[0]);
        regs[0] = (uint32_t)_wtol(s.c_str()); return true;
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
        uint32_t slen = (uint32_t)src.size();
        for (uint32_t i = 0; i < count && i < slen; i++) mem.Write8(dst + i, (uint8_t)src[i]);
        /* Null-terminate only if buffer has room beyond the string content */
        if (slen < count) mem.Write8(dst + slen, 0);
        regs[0] = slen; return true;
    });
    Thunk("mbstowcs", 76, [this](uint32_t* regs, EmulatedMemory& mem) -> bool {
        std::string src = ReadStringFromEmu(mem, regs[1]);
        uint32_t dst = regs[0], count = regs[2];
        if (dst == 0) { regs[0] = (uint32_t)src.size(); return true; } /* just count */
        uint32_t n = std::min(count, (uint32_t)src.size());
        for (uint32_t i = 0; i < n; i++) mem.Write16(dst+i*2, (uint16_t)(uint8_t)src[i]);
        if (n < count) mem.Write16(dst + n*2, 0); /* null-terminate if room */
        regs[0] = n; return true;
    });
    Thunk("wcstok", 77, [this](uint32_t* regs, EmulatedMemory& mem) -> bool {
        /* WinCE wcstok(str, delimiters) - 2-arg like POSIX strtok.
           str=NULL means continue from saved position. */
        static uint32_t saved_pos = 0;
        uint32_t str_addr = regs[0];
        uint32_t delim_addr = regs[1];
        std::wstring delim = ReadWStringFromEmu(mem, delim_addr);
        if (str_addr != 0) saved_pos = str_addr;
        if (saved_pos == 0) { regs[0] = 0; return true; }
        /* Skip leading delimiters */
        uint32_t pos = saved_pos;
        while (true) {
            uint16_t ch = mem.Read16(pos);
            if (ch == 0) { saved_pos = 0; regs[0] = 0; return true; }
            bool is_delim = false;
            for (wchar_t d : delim) if ((uint16_t)d == ch) { is_delim = true; break; }
            if (!is_delim) break;
            pos += 2;
        }
        /* pos now points to start of token */
        uint32_t token_start = pos;
        /* Find end of token */
        while (true) {
            uint16_t ch = mem.Read16(pos);
            if (ch == 0) { saved_pos = 0; break; }
            bool is_delim = false;
            for (wchar_t d : delim) if ((uint16_t)d == ch) { is_delim = true; break; }
            if (is_delim) { mem.Write16(pos, 0); saved_pos = pos + 2; break; }
            pos += 2;
        }
        std::wstring tok = ReadWStringFromEmu(mem, token_start);
        static int wcstok_log_count = 0;
        if (wcstok_log_count < 30) { wcstok_log_count++; LOG(API, "[API] wcstok('%ls') -> 0x%08X '%ls'\n", delim.c_str(), token_start, tok.substr(0,40).c_str()); }
        regs[0] = token_start;
        return true;
    });
    Thunk("wcspbrk", [this](uint32_t* regs, EmulatedMemory& mem) -> bool {
        /* wcspbrk(str, charset) - find first char in str that's in charset */
        uint32_t str_addr = regs[0], cs_addr = regs[1];
        std::wstring charset = ReadWStringFromEmu(mem, cs_addr);
        uint32_t pos = str_addr;
        while (true) {
            uint16_t ch = mem.Read16(pos);
            if (ch == 0) { regs[0] = 0; return true; }
            for (wchar_t d : charset) if ((uint16_t)d == ch) { regs[0] = pos; return true; }
            pos += 2;
        }
    });
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
    /* swscanf(wchar_t* input, wchar_t* format, ...) — scanf from wide string */
    Thunk("swscanf", 1098, [this](uint32_t* regs, EmulatedMemory& mem) -> bool {
        std::wstring input = ReadWStringFromEmu(mem, regs[0]);
        std::wstring fmt = ReadWStringFromEmu(mem, regs[1]);
        /* Collect output pointer args: r2, r3, then stack */
        uint32_t out_ptrs[10];
        out_ptrs[0] = regs[2]; out_ptrs[1] = regs[3];
        for (int i = 2; i < 10; i++) out_ptrs[i] = ReadStackArg(regs, mem, i - 2);
        /* Simple scanf parser: supports %d, %u, %x, %s, %c, %f, %ld, %lu, %lx */
        int matched = 0;
        size_t ipos = 0; /* position in input */
        size_t fpos = 0; /* position in format */
        int outi = 0;    /* output pointer index */
        while (fpos < fmt.size() && ipos < input.size()) {
            wchar_t fc = fmt[fpos];
            if (fc == L'%') {
                fpos++;
                /* Skip width specifiers and 'l' modifier */
                while (fpos < fmt.size() && (fmt[fpos] == L'l' || fmt[fpos] == L'h' ||
                       (fmt[fpos] >= L'0' && fmt[fpos] <= L'9'))) fpos++;
                if (fpos >= fmt.size()) break;
                wchar_t spec = fmt[fpos++];
                /* Skip whitespace in input */
                while (ipos < input.size() && (input[ipos] == L' ' || input[ipos] == L'\t')) ipos++;
                if (spec == L'd' || spec == L'i') {
                    /* Parse signed integer */
                    bool neg = false;
                    if (ipos < input.size() && input[ipos] == L'-') { neg = true; ipos++; }
                    else if (ipos < input.size() && input[ipos] == L'+') ipos++;
                    if (ipos >= input.size() || input[ipos] < L'0' || input[ipos] > L'9') break;
                    int32_t val = 0;
                    while (ipos < input.size() && input[ipos] >= L'0' && input[ipos] <= L'9')
                        val = val * 10 + (input[ipos++] - L'0');
                    if (neg) val = -val;
                    if (outi < 10) mem.Write32(out_ptrs[outi++], (uint32_t)val);
                    matched++;
                } else if (spec == L'u') {
                    if (ipos >= input.size() || input[ipos] < L'0' || input[ipos] > L'9') break;
                    uint32_t val = 0;
                    while (ipos < input.size() && input[ipos] >= L'0' && input[ipos] <= L'9')
                        val = val * 10 + (input[ipos++] - L'0');
                    if (outi < 10) mem.Write32(out_ptrs[outi++], val);
                    matched++;
                } else if (spec == L'x' || spec == L'X') {
                    /* Skip optional 0x prefix */
                    if (ipos + 1 < input.size() && input[ipos] == L'0' && (input[ipos+1] == L'x' || input[ipos+1] == L'X'))
                        ipos += 2;
                    if (ipos >= input.size()) break;
                    uint32_t val = 0;
                    bool got = false;
                    while (ipos < input.size()) {
                        wchar_t c = input[ipos];
                        if (c >= L'0' && c <= L'9') { val = val * 16 + (c - L'0'); got = true; ipos++; }
                        else if (c >= L'a' && c <= L'f') { val = val * 16 + (c - L'a' + 10); got = true; ipos++; }
                        else if (c >= L'A' && c <= L'F') { val = val * 16 + (c - L'A' + 10); got = true; ipos++; }
                        else break;
                    }
                    if (!got) break;
                    if (outi < 10) mem.Write32(out_ptrs[outi++], val);
                    matched++;
                } else if (spec == L's') {
                    /* Read non-whitespace characters into wide string pointer */
                    uint32_t dst = out_ptrs[outi++];
                    uint32_t off = 0;
                    while (ipos < input.size() && input[ipos] != L' ' && input[ipos] != L'\t' && input[ipos] != L'\n')
                        mem.Write16(dst + off++ * 2, input[ipos++]);
                    mem.Write16(dst + off * 2, 0);
                    matched++;
                } else if (spec == L'c') {
                    if (outi < 10) mem.Write16(out_ptrs[outi++], input[ipos++]);
                    matched++;
                } else {
                    /* Unknown specifier, skip */
                    break;
                }
            } else if (fc == L' ' || fc == L'\t') {
                /* Whitespace in format matches zero or more whitespace in input */
                fpos++;
                while (ipos < input.size() && (input[ipos] == L' ' || input[ipos] == L'\t')) ipos++;
            } else {
                /* Literal character match */
                if (input[ipos] != fc) break;
                fpos++; ipos++;
            }
        }
        LOG(API, "[API] swscanf('%ls', '%ls') -> %d\n", input.c_str(), fmt.c_str(), matched);
        regs[0] = (uint32_t)matched;
        return true;
    });
    thunk_handlers["wvsprintfW"] = thunk_handlers["_snwprintf"];
    ThunkOrdinal("sin", 1058);  /* sin @1058 is implemented in crt.cpp */
    /* sprintf(char* buf, const char* fmt, ...) — narrow printf */
    Thunk("sprintf", 719, [this](uint32_t* regs, EmulatedMemory& mem) -> bool {
        uint32_t dst_addr = regs[0];
        std::string fmt = ReadStringFromEmu(mem, regs[1]);
        uint32_t args[10];
        args[0] = regs[2]; args[1] = regs[3];
        for (int i = 2; i < 10; i++) args[i] = ReadStackArg(regs, mem, i - 2);
        /* Process format string, assembling output */
        std::string result;
        int arg_idx = 0;
        for (size_t i = 0; i < fmt.size(); i++) {
            if (fmt[i] == '%' && i + 1 < fmt.size()) {
                i++;
                if (fmt[i] == '%') { result += '%'; continue; }
                /* Collect the full format specifier */
                std::string spec_str = "%";
                while (i < fmt.size() && !isalpha(fmt[i]) && fmt[i] != '%') { spec_str += fmt[i]; i++; }
                if (i >= fmt.size()) break;
                char spec = fmt[i]; spec_str += spec;
                if (arg_idx >= 10) { result += '?'; continue; }
                char buf[128];
                if (spec == 'd' || spec == 'i') {
                    snprintf(buf, sizeof(buf), spec_str.c_str(), (int)args[arg_idx++]);
                    result += buf;
                } else if (spec == 'u') {
                    snprintf(buf, sizeof(buf), spec_str.c_str(), args[arg_idx++]);
                    result += buf;
                } else if (spec == 'x' || spec == 'X' || spec == 'o') {
                    snprintf(buf, sizeof(buf), spec_str.c_str(), args[arg_idx++]);
                    result += buf;
                } else if (spec == 's') {
                    std::string s = ReadStringFromEmu(mem, args[arg_idx++]);
                    snprintf(buf, sizeof(buf), spec_str.c_str(), s.c_str());
                    result += buf;
                } else if (spec == 'S') {
                    /* %S = wide string in WinCE narrow printf */
                    std::wstring ws = ReadWStringFromEmu(mem, args[arg_idx++]);
                    std::string ns(ws.begin(), ws.end());
                    result += ns;
                } else if (spec == 'c') {
                    snprintf(buf, sizeof(buf), spec_str.c_str(), (char)args[arg_idx++]);
                    result += buf;
                } else if (spec == 'f' || spec == 'e' || spec == 'E' || spec == 'g' || spec == 'G') {
                    if (arg_idx + 1 < 10) {
                        uint64_t bits = ((uint64_t)args[arg_idx + 1] << 32) | args[arg_idx];
                        double val; memcpy(&val, &bits, 8); arg_idx += 2;
                        snprintf(buf, sizeof(buf), spec_str.c_str(), val);
                        result += buf;
                    } else { result += '?'; arg_idx = 10; }
                } else if (spec == 'p') {
                    snprintf(buf, sizeof(buf), "%08X", args[arg_idx++]);
                    result += buf;
                } else { result += '?'; arg_idx++; }
            } else result += fmt[i];
        }
        uint8_t* dst = mem.Translate(dst_addr);
        if (dst) { memcpy(dst, result.c_str(), result.size() + 1); }
        regs[0] = (uint32_t)result.size();
        return true;
    });
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

    /* StringCbCopyW(dst, cbDest, src) — byte-count version of StringCchCopyW */
    Thunk("StringCbCopyW", 1690, [this](uint32_t* regs, EmulatedMemory& mem) -> bool {
        uint32_t dst = regs[0], cb = regs[1], src_ptr = regs[2];
        uint32_t cch = cb / 2;
        if (!dst || cch == 0) { regs[0] = 0x80070057; return true; }
        std::wstring src = ReadWStringFromEmu(mem, src_ptr);
        uint32_t copy_len = std::min((uint32_t)src.size(), cch - 1);
        for (uint32_t i = 0; i < copy_len; i++) mem.Write16(dst + i * 2, src[i]);
        mem.Write16(dst + copy_len * 2, 0);
        regs[0] = (src.size() >= cch) ? 0x8007007A : 0;
        return true;
    });
    /* StringCbCatW(dst, cbDest, src) — byte-count version of StringCchCatW */
    Thunk("StringCbCatW", 1694, [this](uint32_t* regs, EmulatedMemory& mem) -> bool {
        uint32_t dst = regs[0], cb = regs[1], src_ptr = regs[2];
        uint32_t cch = cb / 2;
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
    /* StringCchCatExW(dst, cchDest, src, ppszDestEnd, pcchRemaining, dwFlags) */
    Thunk("StringCchCatExW", 1695, [this](uint32_t* regs, EmulatedMemory& mem) -> bool {
        uint32_t dst = regs[0], cch = regs[1], src_ptr = regs[2], ppEnd = regs[3];
        uint32_t pcchRemaining = ReadStackArg(regs, mem, 0);
        if (!dst || cch == 0) { regs[0] = 0x80070057; return true; }
        std::wstring existing = ReadWStringFromEmu(mem, dst);
        std::wstring src = ReadWStringFromEmu(mem, src_ptr);
        uint32_t cur_len = (uint32_t)existing.size();
        uint32_t avail = (cur_len < cch) ? cch - cur_len - 1 : 0;
        uint32_t copy_len = std::min((uint32_t)src.size(), avail);
        for (uint32_t i = 0; i < copy_len; i++) mem.Write16(dst + (cur_len + i) * 2, src[i]);
        mem.Write16(dst + (cur_len + copy_len) * 2, 0);
        if (ppEnd) mem.Write32(ppEnd, dst + (cur_len + copy_len) * 2);
        if (pcchRemaining) mem.Write32(pcchRemaining, cch - cur_len - copy_len);
        regs[0] = (src.size() > avail) ? 0x8007007A : 0;
        return true;
    });
    /* StringCbCatExW(dst, cbDest, src, ppszDestEnd, pcbRemaining, dwFlags) */
    Thunk("StringCbCatExW", 1696, [this](uint32_t* regs, EmulatedMemory& mem) -> bool {
        uint32_t dst = regs[0], cb = regs[1], src_ptr = regs[2], ppEnd = regs[3];
        uint32_t pcbRemaining = ReadStackArg(regs, mem, 0);
        uint32_t cch = cb / 2;
        if (!dst || cch == 0) { regs[0] = 0x80070057; return true; }
        std::wstring existing = ReadWStringFromEmu(mem, dst);
        std::wstring src = ReadWStringFromEmu(mem, src_ptr);
        uint32_t cur_len = (uint32_t)existing.size();
        uint32_t avail = (cur_len < cch) ? cch - cur_len - 1 : 0;
        uint32_t copy_len = std::min((uint32_t)src.size(), avail);
        for (uint32_t i = 0; i < copy_len; i++) mem.Write16(dst + (cur_len + i) * 2, src[i]);
        mem.Write16(dst + (cur_len + copy_len) * 2, 0);
        if (ppEnd) mem.Write32(ppEnd, dst + (cur_len + copy_len) * 2);
        if (pcbRemaining) mem.Write32(pcbRemaining, (cch - cur_len - copy_len) * 2);
        regs[0] = (src.size() > avail) ? 0x8007007A : 0;
        return true;
    });
    /* StringCchPrintfExW(dst, cchDest, ppszDestEnd, pcchRemaining, dwFlags, pszFormat, ...) */
    Thunk("StringCchPrintfExW", 1701, [this, wprintf_format](uint32_t* regs, EmulatedMemory& mem) -> bool {
        uint32_t dst = regs[0], cch = regs[1], ppEnd = regs[2], pcchRemaining = regs[3];
        uint32_t dwFlags = ReadStackArg(regs, mem, 0);
        uint32_t fmtPtr = ReadStackArg(regs, mem, 1);
        if (!dst || cch == 0) { regs[0] = 0x80070057; return true; }
        std::wstring fmt = ReadWStringFromEmu(mem, fmtPtr);
        uint32_t args[10];
        for (int i = 0; i < 10; i++) args[i] = ReadStackArg(regs, mem, 2 + i);
        std::wstring result = wprintf_format(mem, fmt, args, 10);
        uint32_t copy_len = std::min((uint32_t)result.size(), cch - 1);
        for (uint32_t i = 0; i < copy_len; i++) mem.Write16(dst + i * 2, result[i]);
        mem.Write16(dst + copy_len * 2, 0);
        if (ppEnd) mem.Write32(ppEnd, dst + copy_len * 2);
        if (pcchRemaining) mem.Write32(pcchRemaining, cch - copy_len);
        regs[0] = (result.size() >= cch) ? 0x8007007A : 0;
        (void)dwFlags;
        return true;
    });
    /* StringCchCopyNW(dst, cchDest, src, cchToCopy) */
    Thunk("StringCchCopyNW", 1742, [this](uint32_t* regs, EmulatedMemory& mem) -> bool {
        uint32_t dst = regs[0], cch = regs[1], src_ptr = regs[2], cchToCopy = regs[3];
        if (!dst || cch == 0) { regs[0] = 0x80070057; return true; }
        std::wstring src = ReadWStringFromEmu(mem, src_ptr);
        uint32_t src_len = std::min((uint32_t)src.size(), cchToCopy);
        uint32_t copy_len = std::min(src_len, cch - 1);
        for (uint32_t i = 0; i < copy_len; i++) mem.Write16(dst + i * 2, src[i]);
        mem.Write16(dst + copy_len * 2, 0);
        regs[0] = (src_len >= cch) ? 0x8007007A : 0;
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
        LOG(API, "[API] LCMapStringW(locale=0x%X, flags=0x%X, src=0x%08X, srcLen=%d) -> 0 (stub)\n",
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

    /* vswprintf(dst, format, va_list) — va_list on ARM is a pointer to args in memory */
    Thunk("vswprintf", 1099, [this, wprintf_format](uint32_t* regs, EmulatedMemory& mem) -> bool {
        uint32_t dst = regs[0];
        std::wstring fmt = ReadWStringFromEmu(mem, regs[1]);
        uint32_t va_ptr = regs[2]; /* ARM va_list = pointer to arg array */
        uint32_t args[10];
        for (int i = 0; i < 10; i++) args[i] = mem.Read32(va_ptr + i * 4);
        std::wstring result = wprintf_format(mem, fmt, args, 10);
        for (uint32_t i = 0; i < (uint32_t)result.size(); i++) mem.Write16(dst + i * 2, result[i]);
        mem.Write16(dst + (uint32_t)result.size() * 2, 0);
        LOG(API, "[API] vswprintf('%ls') -> '%ls'\n", fmt.c_str(), result.c_str());
        regs[0] = (uint32_t)result.size();
        return true;
    });
}
