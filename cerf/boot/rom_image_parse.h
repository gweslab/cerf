#pragma once

#include "rom_parser_service.h"

#include <cstddef>
#include <cstdint>
#include <span>
#include <vector>

/* Pure functions for parsing the CE ROM image binary format
   (B000FF, NB0, ECEC marker, ROMHDR, TOC, IMGFS). All callers go
   through these - RomParserService composes them; nothing here
   depends on any Service. */

namespace cerf::rom_image_parse {

constexpr size_t   kRomHdrSize           = 84;
constexpr size_t   kTocEntrySize         = 32;
constexpr size_t   kFileEntrySize        = 28;

constexpr uint32_t kRomSignature         = 0x43454345u;
constexpr uint32_t kRomSignatureOffset   = 0x40u;

/* B000FF container header bytes. */
constexpr uint8_t  kB000FFSignature[7]   = {'B','0','0','0','F','F','\n'};
constexpr size_t   kB000FFSectionHeaderSize = 12;

/* IMGFS - superblock 16-byte UUID per imgfs.py. */
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

bool AssembleB000FFFlat(const std::vector<uint8_t>&  raw,
                        std::vector<uint8_t>&       out_flat,
                        uint32_t&                   out_base_va,
                        uint32_t&                   out_entry_va,
                        std::vector<B000FFSection>& out_sections);

bool B000FFSectionTable(std::span<const uint8_t>    raw,
                        std::vector<B000FFSection>& out_sections,
                        uint32_t&                   out_image_start,
                        uint32_t&                   out_image_length,
                        uint32_t&                   out_terminator);

/* "NOSAJ\0" magic - the SmartBook G138 ".fim" flash-packaging container. */
constexpr uint8_t kNosajSignature[6] = {'N', 'O', 'S', 'A', 'J', '\0'};

struct NosajOsXip {
    size_t   data_off  = 0;   /* file offset of OS XIP data (after launch block) */
    uint32_t flat_size = 0;   /* image span = physlast - physfirst                */
    uint32_t base_va   = 0;   /* physfirst - file offset 0 of the XIP maps here    */
    uint32_t entry_va  = 0;   /* kernel entry kernel-VA                            */
};

/* Resolve the bootable OS XIP in a NOSAJ container; false if absent/unresolvable. */
bool NosajLocateOsXip(std::span<const uint8_t> raw, NosajOsXip& out);

/* "ARNOLDBOOTBLOCK\0" magic - the Siemens SIMpad ("Arnold" codename) flash
   firmware package (the original S842-SI-*.bin update files). A fixed header
   prefixes the bootable OS XIP; the XIP itself is byte-for-byte what an extracted
   .nb0 carries (the genuine ROM that runs on real SIMpad hardware). */
constexpr uint8_t kArnoldSignature[16] = {
    'A', 'R', 'N', 'O', 'L', 'D', 'B', 'O',
    'O', 'T', 'B', 'L', 'O', 'C', 'K', '\0'};

struct ArnoldOsXip {
    size_t   data_off  = 0;   /* file offset of the OS XIP (after the header)  */
    uint32_t flat_size = 0;   /* XIP span in the file (header-stripped tail)   */
    uint32_t base_va   = 0;   /* physfirst - file offset data_off maps here    */
};

/* Resolve the bootable OS XIP in a Siemens ARNOLDBOOTBLOCK package; false if
   absent/unresolvable. */
bool ArnoldLocateOsXip(std::span<const uint8_t> raw, ArnoldOsXip& out);

/* First ECEC ROM signature at/after `start` whose pTOC (+4) is a kernel VA
   (0x80000000..0xC0000000); SIZE_MAX if none. Locates the XIP inside a
   fixed-header firmware package without trusting a header-length constant. */
size_t FindXipEcec(std::span<const uint8_t> raw, size_t start);

/* "iPAQ " banner - the Compaq/HP iPAQ h3xxx ".nbf" firmware update format: a
   32-byte ASCII version banner ("iPAQ 3600-ENG-2.14-...") then the bootable OS
   XIP. A distinct OEM format from a raw .nb0; its payload happens to match an
   extracted .nb0 byte-for-byte. */
constexpr uint8_t kIpaqNbfSignature[5] = {'i', 'P', 'A', 'Q', ' '};

struct IpaqNbfOsXip {
    size_t   data_off  = 0;   /* file offset of the OS XIP (after the banner) */
    uint32_t flat_size = 0;   /* XIP span in the file                         */
};

/* Resolve the bootable OS XIP in a Compaq iPAQ .nbf package; false if
   absent/unresolvable. */
bool IpaqNbfLocateOsXip(std::span<const uint8_t> raw, IpaqNbfOsXip& out);

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

bool ResolveRomhdrStructural(std::span<const uint8_t> flat,
                             ParsedXipRegion&         out,
                             size_t&                  out_romhdr_off);

bool ResolveNextStructuralXip(std::span<const uint8_t> flat,
                              size_t                   start_off,
                              uint32_t                 flat_base_va,
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
