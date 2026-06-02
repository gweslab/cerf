#pragma once

#include "rom_parser_service.h"

#include <cstddef>
#include <cstdint>
#include <span>
#include <vector>

/* Pure functions for parsing the CE ROM image binary format
   (B000FF, NB0, ECEC marker, ROMHDR, TOC, IMGFS). All callers go
   through these — RomParserService composes them; nothing here
   depends on any Service. */

namespace cerf::rom_image_parse {

/* romldr.h struct sizes. */
constexpr size_t   kRomHdrSize           = 84;
constexpr size_t   kTocEntrySize         = 32;
constexpr size_t   kFileEntrySize        = 28;

/* ECEC marker — 'CECE' little-endian = 0x43454345. Sits at
   physfirst+0x40 per romldr.h ROM_SIGNATURE_OFFSET. */
constexpr uint32_t kRomSignature         = 0x43454345u;
constexpr uint32_t kRomSignatureOffset   = 0x40u;

/* B000FF container header bytes. */
constexpr uint8_t  kB000FFSignature[7]   = {'B','0','0','0','F','F','\n'};
constexpr size_t   kB000FFSectionHeaderSize = 12;

/* IMGFS — superblock 16-byte UUID per imgfs.py. */
constexpr uint8_t  kImgfsUuid[16] = {
    0xF8, 0xAC, 0x2C, 0x9D, 0xE3, 0xD4, 0x2B, 0x4D,
    0xBD, 0x30, 0x91, 0x6E, 0xD8, 0x4F, 0x31, 0xDC,
};
constexpr uint32_t kImgfsDirentSize      = 0x34;

inline uint32_t U32(const uint8_t* p, size_t off) {
    return uint32_t(p[off])
         | (uint32_t(p[off + 1]) << 8)
         | (uint32_t(p[off + 2]) << 16)
         | (uint32_t(p[off + 3]) << 24);
}

inline uint16_t U16(const uint8_t* p, size_t off) {
    return uint16_t(p[off]) | (uint16_t(p[off + 1]) << 8);
}

bool AssembleB000FFFlat(const std::vector<uint8_t>& raw,
                        std::vector<uint8_t>& out_flat,
                        uint32_t& out_base_va,
                        uint32_t& out_entry_va);

/* Find every ECEC marker in the first 8 MB of `flat` whose
   ptoc_va / romhdr_off look plausible. Multi-XIP images
   (Pocket PC 2000 NB0, WM6+ NB0 flash dumps) carry one ECEC
   per XIP region. */
std::vector<size_t> FindAllEcec(std::span<const uint8_t> flat);

/* Parse 84 bytes at `flat[off]` as a ROMHDR. Returns false when
   the fields fail validation (dllfirst>dlllast, physfirst>physlast,
   absurd nummods/numfiles). */
bool ParseRomHdr(std::span<const uint8_t> flat,
                 size_t off,
                 ParsedROMHDR& out);

bool ResolveRomhdrAtEcec(std::span<const uint8_t> flat,
                         size_t                   ecec_off,
                         uint32_t                 flat_base_va,
                         ParsedXipRegion&         out,
                         size_t&                  out_romhdr_off);

/* CE2.x ROMs have no ECEC signature record (added in CE3 romldr.h);
   their romimage patches the kernel pTOC directly. Finds the ROMHDR by
   structural scan validating against nk.exe; false when none found. */
bool ResolveRomhdrStructural(std::span<const uint8_t> flat,
                             ParsedXipRegion&         out,
                             size_t&                  out_romhdr_off);

/* Parse `romhdr.nummods` TOCentry records and `romhdr.numfiles`
   FILESentry records starting at `romhdr_off + kRomHdrSize`,
   resolving filenames via `load_offset`. Appends to `toc.modules`
   / `toc.files`. */
void ParseModulesAndFiles(std::span<const uint8_t> flat,
                          size_t                   romhdr_off,
                          uint32_t                 load_offset,
                          const ParsedROMHDR&      romhdr,
                          ParsedTOC&               toc);

/* Locate the IMGFS superblock (page-aligned UUID with valid
   header fields) in `raw`. Returns SIZE_MAX when not present.
   Port of imgfs.py::find_imgfs_base. */
size_t FindImgfsBase(std::span<const uint8_t> raw);

}  /* namespace cerf::rom_image_parse */
