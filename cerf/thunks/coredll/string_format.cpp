/* String format thunks: printf/scanf family, wprintf_format helper */
#define NOMINMAX
#include "../win32_thunks.h"
#include "../../log.h"
#include <cstdio>
#include <vector>

/* WprintfFormat: parse wide format string with args from ARM registers/stack */
std::wstring Win32Thunks::WprintfFormat(EmulatedMemory& mem, const std::wstring& fmt,
                                         uint32_t* args, int nargs) {
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
}

void Win32Thunks::RegisterStringFormatHandlers() {
    Thunk("wsprintfW", 56, [this](uint32_t* regs, EmulatedMemory& mem) -> bool {
        uint32_t dst_addr = regs[0];
        std::wstring fmt = ReadWStringFromEmu(mem, regs[1]);
        uint32_t args[10];
        args[0] = regs[2]; args[1] = regs[3];
        for (int i = 2; i < 10; i++) args[i] = ReadStackArg(regs, mem, i - 2);
        std::wstring result = WprintfFormat(mem, fmt, args, 10);
        for (size_t i = 0; i < result.size(); i++) mem.Write16(dst_addr + (uint32_t)i * 2, result[i]);
        mem.Write16(dst_addr + (uint32_t)result.size() * 2, 0);
        regs[0] = (uint32_t)result.size();
        return true;
    });
    Thunk("_snwprintf", 1096, [this](uint32_t* regs, EmulatedMemory& mem) -> bool {
        uint32_t dst = regs[0], count = regs[1];
        std::wstring fmt = ReadWStringFromEmu(mem, regs[2]);
        uint32_t args[10];
        args[0] = regs[3];
        for (int i = 1; i < 10; i++) args[i] = ReadStackArg(regs, mem, i - 1);
        std::wstring result = WprintfFormat(mem, fmt, args, 10);
        uint32_t copy_len = std::min((uint32_t)result.size(), count > 0 ? count - 1 : 0u);
        for (uint32_t i = 0; i < copy_len; i++) mem.Write16(dst + i * 2, result[i]);
        if (count > 0) mem.Write16(dst + copy_len * 2, 0);
        regs[0] = (uint32_t)result.size();
        return true;
    });
    /* swprintf(dst, format, ...) — NO count param, unlike _snwprintf */
    Thunk("swprintf", 1097, [this](uint32_t* regs, EmulatedMemory& mem) -> bool {
        uint32_t dst = regs[0];
        std::wstring fmt = ReadWStringFromEmu(mem, regs[1]);
        uint32_t args[10];
        args[0] = regs[2];
        args[1] = regs[3];
        for (int i = 2; i < 10; i++) args[i] = ReadStackArg(regs, mem, i - 2);
        std::wstring result = WprintfFormat(mem, fmt, args, 10);
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
    ThunkOrdinal("wvsprintfW", 57);
    ThunkOrdinal("swprintf", 1097);
    ThunkOrdinal("swscanf", 1098);
    /* vswprintf(dst, format, va_list) — va_list on ARM is a pointer to args in memory */
    Thunk("vswprintf", 1099, [this](uint32_t* regs, EmulatedMemory& mem) -> bool {
        uint32_t dst = regs[0];
        std::wstring fmt = ReadWStringFromEmu(mem, regs[1]);
        uint32_t va_ptr = regs[2]; /* ARM va_list = pointer to arg array */
        uint32_t args[10];
        for (int i = 0; i < 10; i++) args[i] = mem.Read32(va_ptr + i * 4);
        std::wstring result = WprintfFormat(mem, fmt, args, 10);
        for (uint32_t i = 0; i < (uint32_t)result.size(); i++) mem.Write16(dst + i * 2, result[i]);
        mem.Write16(dst + (uint32_t)result.size() * 2, 0);
        LOG(API, "[API] vswprintf('%ls') -> '%ls'\n", fmt.c_str(), result.c_str());
        regs[0] = (uint32_t)result.size();
        return true;
    });
}
