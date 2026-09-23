#include "compactflash_fat_common.h"

#include "../../core/byte_order.h"

#include <cstdio>
#include <cstring>

namespace cf_fat {

std::wstring BaseName(const std::wstring& path) {
    const std::size_t s = path.find_last_of(L"\\/");
    return s == std::wstring::npos ? path : path.substr(s + 1);
}

std::vector<uint8_t> ReadHostFile(const std::wstring& path) {
    std::vector<uint8_t> data;
    std::FILE* f = nullptr;
    if (_wfopen_s(&f, path.c_str(), L"rb") != 0 || !f) return data;
    std::fseek(f, 0, SEEK_END);
    const long n = std::ftell(f);
    std::fseek(f, 0, SEEK_SET);
    if (n > 0) {
        data.resize(static_cast<std::size_t>(n));
        if (std::fread(data.data(), 1, data.size(), f) != data.size()) data.clear();
    }
    std::fclose(f);
    return data;
}

uint8_t LfnChecksum(const uint8_t sfn[11]) {
    uint8_t sum = 0;
    for (int i = 0; i < 11; ++i)
        sum = static_cast<uint8_t>(((sum & 1) << 7) + (sum >> 1) + sfn[i]);
    return sum;
}

namespace {

/* Chars valid in an 8.3 short name without mangling (FAT spec + the allowed
   symbol set). Lowercase is admitted here and folded via the case flags. */
bool Sfn83Char(wchar_t c) {
    if ((c >= L'A' && c <= L'Z') || (c >= L'a' && c <= L'z') ||
        (c >= L'0' && c <= L'9')) return true;
    switch (c) {
        case L'_': case L'-': case L'~': case L'!': case L'#': case L'$':
        case L'%': case L'&': case L'\'': case L'(': case L')': case L'@':
        case L'^': case L'`': case L'{': case L'}': return true;
        default: return false;
    }
}
bool AllSfn83(const std::wstring& s) {
    for (wchar_t c : s) if (!Sfn83Char(c)) return false;
    return true;
}
bool HasLower(const std::wstring& s) {
    for (wchar_t c : s) if (c >= L'a' && c <= L'z') return true;
    return false;
}
bool HasUpper(const std::wstring& s) {
    for (wchar_t c : s) if (c >= L'A' && c <= L'Z') return true;
    return false;
}
uint8_t UpAscii(wchar_t c) {
    return (c >= L'a' && c <= L'z') ? static_cast<uint8_t>(c - 32)
                                    : static_cast<uint8_t>(c);
}

}  /* namespace */

void MakeMangledSfn(const std::wstring& name, int mangle_index, uint8_t out[11]) {
    for (int i = 0; i < 11; ++i) out[i] = ' ';
    const std::size_t dot = name.find_last_of(L'.');
    std::wstring base = dot == std::wstring::npos ? name : name.substr(0, dot);
    std::wstring ext  = dot == std::wstring::npos ? L"" : name.substr(dot + 1);

    auto sanitize = [](wchar_t c) -> uint8_t {
        if (c >= L'a' && c <= L'z') return static_cast<uint8_t>(c - 32);
        if ((c >= L'A' && c <= L'Z') || (c >= L'0' && c <= L'9')) return (uint8_t)c;
        return '_';
    };
    char tail[8];
    const int tn = std::snprintf(tail, sizeof(tail), "~%d", mangle_index);
    int bcap = 8 - tn;
    int bi = 0;
    for (std::size_t i = 0; i < base.size() && bi < bcap; ++i) out[bi++] = sanitize(base[i]);
    for (int i = 0; i < tn; ++i) out[bi++] = static_cast<uint8_t>(tail[i]);
    int ei = 0;
    for (std::size_t i = 0; i < ext.size() && ei < 3; ++i) out[8 + ei++] = sanitize(ext[i]);
}

ShortName MakeShortName(const std::wstring& name, int mangle_index) {
    ShortName r;
    for (int i = 0; i < 11; ++i) r.sfn[i] = ' ';
    r.ntres = 0;
    r.needs_lfn = false;

    const std::size_t dot = name.find_last_of(L'.');
    std::wstring base = dot == std::wstring::npos ? name : name.substr(0, dot);
    std::wstring ext  = dot == std::wstring::npos ? L"" : name.substr(dot + 1);

    const bool fits = !base.empty() && base.size() <= 8 && ext.size() <= 3 &&
                      AllSfn83(base) && AllSfn83(ext);
    if (!fits) {
        MakeMangledSfn(name, mangle_index, r.sfn);
        r.needs_lfn = true;
        return r;
    }
    for (std::size_t i = 0; i < base.size(); ++i) r.sfn[i]     = UpAscii(base[i]);
    for (std::size_t i = 0; i < ext.size();  ++i) r.sfn[8 + i] = UpAscii(ext[i]);
    /* Mixed case cannot be recovered from the SFN + a single flag, so keep an
       LFN; a pure-case name folds to the SFN via the NT case flags, no LFN. */
    if ((HasLower(base) && HasUpper(base)) || (HasLower(ext) && HasUpper(ext))) {
        r.needs_lfn = true;
    } else {
        r.ntres = static_cast<uint8_t>((HasLower(base) ? 0x08 : 0) |
                                       (HasLower(ext)  ? 0x10 : 0));
    }
    return r;
}

uint32_t LfnSlotCount(const std::wstring& name) {
    return static_cast<uint32_t>((name.size() + 12) / 13);
}

uint8_t* EmitFileDir(uint8_t* dir, const std::wstring& name, const uint8_t sfn[11],
                     uint32_t lfn_count, uint8_t ntres, uint32_t first_clus, uint32_t size) {
    const uint8_t sum = LfnChecksum(sfn);
    for (int seq = static_cast<int>(lfn_count); seq >= 1; --seq) {
        uint8_t* le = dir;
        le[0] = static_cast<uint8_t>(seq | (seq == static_cast<int>(lfn_count) ? 0x40 : 0));
        le[11] = 0x0F;     /* ATTR_LONG_NAME */
        le[13] = sum;
        const int base = (seq - 1) * 13;
        const int slots[13] = {1,3,5,7,9, 14,16,18,20,22,24, 28,30};
        for (int i = 0; i < 13; ++i) {
            const int ci = base + i;
            uint16_t ch;
            if (ci < static_cast<int>(name.size())) ch = (uint16_t)name[ci];
            else if (ci == static_cast<int>(name.size())) ch = 0x0000;
            else ch = 0xFFFF;
            cerf::le::Put16(le + slots[i], ch);
        }
        dir += 32;
    }
    std::memcpy(dir, sfn, 11);
    dir[11] = 0x20;        /* ATTR_ARCHIVE */
    dir[12] = ntres;
    cerf::le::Put16(dir + 20, static_cast<uint16_t>(first_clus >> 16));
    cerf::le::Put16(dir + 26, static_cast<uint16_t>(first_clus & 0xFFFF));
    cerf::le::Put32(dir + 28, size);
    return dir + 32;
}

}  /* namespace cf_fat */
