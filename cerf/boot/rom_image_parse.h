#pragma once

#include "rom_parser_service.h"
#include "rom_record_layout.h"

#include <cstddef>
#include <cstdint>
#include <span>
#include <vector>

/* Pure functions for parsing the CE ROM image binary format
   (B000FF, NB0, ECEC marker, ROMHDR, TOC, IMGFS). All callers go
   through these - RomParserService composes them; nothing here
   depends on any Service. */

namespace cerf::rom_image_parse {

/* B000FF container header bytes. */
constexpr uint8_t  kB000FFSignature[7]   = {'B','0','0','0','F','F','\n'};
constexpr size_t   kB000FFSectionHeaderSize = 12;

bool AssembleB000FFFlat(const std::vector<uint8_t>&  raw,
                        std::vector<uint8_t>&       out_flat,
                        uint32_t&                   out_base_va,
                        uint32_t&                   out_entry_va,
                        std::vector<B000FFSection>& out_sections);

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

struct EcecRecord {
    size_t   off        = 0;
    uint32_t ptoc       = 0;
    uint32_t romhdr_off = 0;
};

bool ReadEcec(std::span<const uint8_t> bytes, size_t ecec_off, EcecRecord& out);

bool FindXipEcec(std::span<const uint8_t> raw, size_t start, EcecRecord& out);

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

std::vector<EcecRecord> FindAllEcec(std::span<const uint8_t> flat);

/* Parse 84 bytes at `flat[off]` as a ROMHDR. Returns false when
   the fields fail validation (dllfirst>dlllast, physfirst>physlast,
   absurd nummods/numfiles). */
bool ParseRomHdr(std::span<const uint8_t> flat,
                 size_t off,
                 ParsedROMHDR& out);

inline size_t SelfLocatingRomhdrOffset(uint32_t ptoc, uint32_t physfirst) {
    return size_t(ptoc - physfirst);
}

bool ParseSelfLocatingRomhdr(std::span<const uint8_t> xip,
                             uint32_t                 ptoc,
                             uint32_t                 physfirst,
                             ParsedROMHDR&            out);

template <typename Accept>
bool FindSelfLocatingRomhdr(std::span<const uint8_t> xip,
                            uint32_t                 ptoc,
                            uint32_t                 grain,
                            uint32_t                 phase,
                            Accept                   accept,
                            ParsedROMHDR&            out,
                            uint32_t&                out_physfirst) {
    const uint32_t top = ptoc - ((ptoc - phase) & (grain - 1u));
    const uint32_t min =
        (ptoc > uint32_t(xip.size())) ? ptoc - uint32_t(xip.size()) : 0u;
    for (uint32_t pf = top; pf >= min; pf -= grain) {
        if (ParseSelfLocatingRomhdr(xip, ptoc, pf, out) && accept(out)) {
            out_physfirst = pf;
            return true;
        }
        if (pf < min + grain) break;
    }
    return false;
}

template <typename Visit>
bool ForEachParsedRomhdr(std::span<const uint8_t> flat,
                         size_t                   start_off,
                         Visit                    visit) {
    for (size_t off = start_off; off + kRomHdrSize <= flat.size(); off += 4) {
        ParsedROMHDR h;
        if (!ParseRomHdr(flat, off, h)) continue;
        if (visit(off, h)) return true;
    }
    return false;
}

bool ResolveRomhdrAtEcec(std::span<const uint8_t> flat,
                         const EcecRecord&        ecec,
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

struct ImgfsSuperblock {
    size_t   off             = 0;
    uint32_t dirent_size     = 0;
    uint32_t bytes_per_block = 0;
};

bool ReadImgfsSuperblock(std::span<const uint8_t> bytes, size_t off, ImgfsSuperblock& out);

bool FindImgfsBase(std::span<const uint8_t> raw, ImgfsSuperblock& out);

}  /* namespace cerf::rom_image_parse */
