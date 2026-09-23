#pragma once

#include <cstdint>
#include <string>
#include <vector>

namespace cf_fat {

std::wstring BaseName(const std::wstring& path);

std::vector<uint8_t> ReadHostFile(const std::wstring& path);

struct ShortName {
    uint8_t sfn[11];
    uint8_t ntres;      /* NT case flags at dir offset 12 (0x08 base, 0x10 ext) */
    bool    needs_lfn;
};

/* Natural 8.3 short name (+ case flags, no LFN) when the name fits 8.3; a
   "~mangle_index" mangled short name (+ LFN) otherwise. */
ShortName MakeShortName(const std::wstring& name, int mangle_index);

/* Forced "~mangle_index" mangle, for a natural short-name collision fallback. */
void MakeMangledSfn(const std::wstring& name, int mangle_index, uint8_t out[11]);

uint8_t LfnChecksum(const uint8_t sfn[11]);
uint32_t LfnSlotCount(const std::wstring& name);

uint8_t* EmitFileDir(uint8_t* dir, const std::wstring& name, const uint8_t sfn[11],
                     uint32_t lfn_count, uint8_t ntres, uint32_t first_clus, uint32_t size);

}  /* namespace cf_fat */
