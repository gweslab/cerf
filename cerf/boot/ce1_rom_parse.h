#pragma once

#include "rom_parser_service.h"

#include <cstddef>
#include <cstdint>
#include <span>
#include <vector>

namespace cerf::ce1_rom_parse {

constexpr size_t kCe1TocEntrySize  = 0x130;
constexpr size_t kCe1FileEntrySize = 0x12C;
constexpr size_t kCe1NameMax       = 276;

constexpr size_t kCe1TocOffFileSize   = 0x0C;
constexpr size_t kCe1TocOffName       = 0x10;
constexpr size_t kCe1TocOffNtHeaders  = 0x124;
constexpr size_t kCe1TocOffSecHeaders = 0x128;
constexpr size_t kCe1TocOffLoadVa     = 0x12C;

constexpr size_t kCe1FileOffRealSize = 0x0C;
constexpr size_t kCe1FileOffCompSize = 0x10;
constexpr size_t kCe1FileOffName     = 0x14;
constexpr size_t kCe1FileOffLoadVa   = 0x128;

constexpr uint32_t kPeSignature = 0x00004550u;

struct Ce1RomhdrHit {
    size_t       off = 0;
    ParsedROMHDR hdr;
};

std::vector<Ce1RomhdrHit> FindAllCe1Romhdrs(std::span<const uint8_t> flat);

bool ValidateCe1Xip(std::span<const uint8_t> flat,
                    size_t                   romhdr_off,
                    uint32_t                 base_va,
                    const ParsedROMHDR&      romhdr);

void ParseCe1ModulesAndFiles(std::span<const uint8_t> flat,
                             size_t                   romhdr_off,
                             const ParsedROMHDR&      romhdr,
                             ParsedTOC&               toc);

bool ResolveCe1Xips(std::span<const uint8_t>      flat,
                    std::vector<ParsedXipRegion>& out_xips,
                    uint32_t&                     out_base_va);

}  /* namespace cerf::ce1_rom_parse */
