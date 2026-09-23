#define NOMINMAX

#include "rom_image_parse.h"

#include "../core/ascii_z.h"
#include "../core/byte_order.h"
#include "../core/log.h"

#include <algorithm>
#include <cstring>

namespace cerf::rom_image_parse {

namespace {

using cerf::le::U16;
using cerf::le::U32;

using cerf::ReadAsciiZ;

}  /* namespace */

bool AssembleB000FFFlat(const std::vector<uint8_t>&  raw,
                        std::vector<uint8_t>&       out_flat,
                        uint32_t&                   out_base_va,
                        uint32_t&                   out_entry_va,
                        std::vector<B000FFSection>& out_sections) {
    if (raw.size() < 15) return false;
    if (std::memcmp(raw.data(), kB000FFSignature, 7) != 0) return false;

    std::vector<B000FFSection>& sections = out_sections;
    sections.clear();
    out_entry_va = 0;

    size_t off = 15;  /* sig (7) + image start (4) + image length (4) */
    while (off + kB000FFSectionHeaderSize <= raw.size()) {
        uint32_t base = U32(raw.data(), off);
        uint32_t size = U32(raw.data(), off + 4);
        /* checksum at off+8 - ignored. */
        if (base == 0) {
            /* Terminator section (base=0): the loader convention
               reuses the section header's 'size' field as the kernel
               entry-point VA - the only place B000FF encodes where
               execution begins. */
            out_entry_va = size;
            break;
        }
        size_t data_off = off + kB000FFSectionHeaderSize;
        if (data_off + size > raw.size() || size > 0x10000000u) break;
        sections.push_back({base, size, data_off});
        off = data_off + size;
    }
    if (sections.empty()) return false;

    uint32_t min_va  = sections[0].base;
    uint32_t max_end = sections[0].base + sections[0].size;
    for (const auto& s : sections) {
        min_va  = std::min(min_va,  s.base);
        max_end = std::max(max_end, s.base + s.size);
    }

    out_flat.assign(size_t(max_end - min_va), 0);
    for (const auto& s : sections) {
        std::memcpy(out_flat.data() + (s.base - min_va),
                    raw.data() + s.data_off, s.size);
    }
    out_base_va = min_va;
    LOG(Boot, "RomImageParse: B000FF sections=%zu va=0x%08X..0x%08X (%zu KB)\n",
        sections.size(), min_va, max_end, out_flat.size() / 1024);
    return true;
}

bool NosajLocateOsXip(std::span<const uint8_t> raw, NosajOsXip& out) {
    if (raw.size() < 0x60) return false;
    if (std::memcmp(raw.data(), kNosajSignature, sizeof(kNosajSignature)) != 0)
        return false;

    /* "DiAlOgUe" launch-block marker, stored byte-reversed in the image. */
    static const uint8_t kLaunchMarker[8] = {'e', 'U', 'g', 'O', 'l', 'A', 'i', 'D'};

    /* Inline partition descriptors: fixed 0x5C-byte records, the first at the u16
       offset stored at +0x06. Per record: +0x00 next-descriptor file offset (0 =
       last), +0x58 this partition's data file offset. The bootable OS partition's
       data begins with the launch block. */
    constexpr size_t kDescSize = 0x5Cu;
    size_t   desc       = U16(raw.data(), 0x06);
    size_t   launch_off = 0;
    bool     found      = false;
    for (int i = 0; i < 64 && desc + kDescSize <= raw.size(); ++i) {
        const uint32_t next_off  = U32(raw.data(), desc + 0x00);
        const uint32_t start_off = U32(raw.data(), desc + 0x58);
        if (start_off + sizeof(kLaunchMarker) <= raw.size() &&
            std::memcmp(raw.data() + start_off, kLaunchMarker,
                        sizeof(kLaunchMarker)) == 0) {
            launch_off = start_off;
            found      = true;
            break;
        }
        if (next_off == 0 || next_off <= desc || next_off >= raw.size()) break;
        desc = next_off;
    }
    if (!found) return false;

    /* Launch block: marker(8) + physfirst-offset + span + entry-offset, then the
       XIP data. The offsets are RAM-window-relative; pf_off is physfirst's low
       24 bits. */
    if (launch_off + 0x14 > raw.size()) return false;
    const uint32_t pf_off = U32(raw.data(), launch_off + 0x08);
    const uint32_t span   = U32(raw.data(), launch_off + 0x0C);
    const uint32_t en_off = U32(raw.data(), launch_off + 0x10);
    const size_t   xip    = launch_off + 0x14;
    if (span == 0 || en_off < pf_off || xip + span > raw.size()) return false;

    EcecRecord ecec;
    if (!ReadEcec(raw, xip + kRomSignatureOffset, ecec)) return false;

    ParsedROMHDR h;
    uint32_t     pf = 0;
    if (!FindSelfLocatingRomhdr(
            raw.subspan(xip, span), ecec.ptoc, 0x01000000u, pf_off,
            [&](const ParsedROMHDR& c) { return c.physlast - c.physfirst == span; },
            h, pf)) {
        return false;
    }
    out.data_off  = xip;
    out.flat_size = span;
    out.base_va   = pf;
    out.entry_va  = pf + (en_off - pf_off);
    return true;
}

bool ReadEcec(std::span<const uint8_t> bytes, size_t ecec_off, EcecRecord& out) {
    if (ecec_off + kEcecRecordSize > bytes.size()) return false;
    if (U32(bytes.data(), ecec_off) != kRomSignature) return false;
    out.off        = ecec_off;
    out.ptoc       = U32(bytes.data(), ecec_off + kEcecOffPtoc);
    out.romhdr_off = U32(bytes.data(), ecec_off + kEcecOffRomhdr);
    return true;
}

static bool ReadKernelEcec(std::span<const uint8_t> bytes, size_t i, EcecRecord& out) {
    return ReadEcec(bytes, i, out) && out.ptoc >= 0x80000000u && out.ptoc < 0xC0000000u;
}

bool FindXipEcec(std::span<const uint8_t> raw, size_t start, EcecRecord& out) {
    for (size_t i = start; i < raw.size(); ++i) {
        if (ReadKernelEcec(raw, i, out)) return true;
    }
    return false;
}

bool ArnoldLocateOsXip(std::span<const uint8_t> raw, ArnoldOsXip& out) {
    if (raw.size() < sizeof(kArnoldSignature)) return false;
    if (std::memcmp(raw.data(), kArnoldSignature, sizeof(kArnoldSignature)) != 0)
        return false;

    EcecRecord ecec;
    if (!FindXipEcec(raw, sizeof(kArnoldSignature), ecec)) return false;
    if (ecec.off < kRomSignatureOffset) return false;

    const size_t   data_off = ecec.off - kRomSignatureOffset;
    const size_t   xip_size = raw.size() - data_off;
    std::span<const uint8_t> xip = raw.subspan(data_off);

    ParsedROMHDR h;
    uint32_t     base = 0;
    if (!FindSelfLocatingRomhdr(xip, ecec.ptoc, 0x1000u, 0u,
                                [](const ParsedROMHDR&) { return true; }, h, base)) {
        return false;
    }
    out.data_off  = data_off;
    out.flat_size = uint32_t(xip_size);
    out.base_va   = base;
    return true;
}

bool IpaqNbfLocateOsXip(std::span<const uint8_t> raw, IpaqNbfOsXip& out) {
    if (raw.size() < sizeof(kIpaqNbfSignature)) return false;
    if (std::memcmp(raw.data(), kIpaqNbfSignature, sizeof(kIpaqNbfSignature)) != 0)
        return false;

    EcecRecord ecec;
    if (!FindXipEcec(raw, sizeof(kIpaqNbfSignature), ecec)) return false;
    if (ecec.off < kRomSignatureOffset) return false;

    out.data_off  = ecec.off - kRomSignatureOffset;
    out.flat_size = uint32_t(raw.size() - out.data_off);
    return true;
}

std::vector<EcecRecord> FindAllEcec(std::span<const uint8_t> flat) {
    std::vector<EcecRecord> out;
    for (size_t i = 0; i < flat.size(); ++i) {
        EcecRecord ecec;
        if (ReadKernelEcec(flat, i, ecec)) out.push_back(ecec);
    }
    return out;
}

bool ParseRomHdr(std::span<const uint8_t> flat, size_t off, ParsedROMHDR& out) {
    if (off + kRomHdrSize > flat.size()) return false;
    const uint8_t* p = flat.data() + off;
    out.dllfirst        = U32(p, kHdrDllFirstOff);
    out.dlllast         = U32(p, kHdrDllLastOff);
    out.physfirst       = U32(p, kHdrPhysFirstOff);
    out.physlast        = U32(p, kHdrPhysLastOff);
    out.nummods         = U32(p, kHdrNumModsOff);
    out.ulRAMStart      = U32(p, kHdrRAMStartOff);
    out.ulRAMFree       = U32(p, kHdrRAMFreeOff);
    out.ulRAMEnd        = U32(p, kHdrRAMEndOff);
    out.ulCopyEntries   = U32(p, kHdrCopyEntriesOff);
    out.ulCopyOffset    = U32(p, kHdrCopyOffsetOff);
    out.ulProfileLen    = U32(p, kHdrProfileLenOff);
    out.ulProfileOffset = U32(p, kHdrProfileOffsetOff);
    out.numfiles        = U32(p, kHdrNumFilesOff);
    out.ulKernelFlags   = U32(p, kHdrKernelFlagsOff);
    out.ulFSRamPercent  = U32(p, kHdrFSRamPercentOff);
    out.ulDrivglobStart = U32(p, kHdrDrivglobStartOff);
    out.ulDrivglobLen   = U32(p, kHdrDrivglobLenOff);
    out.usCPUType       = U16(p, kHdrCPUTypeOff);
    out.usMiscFlags     = U16(p, kHdrMiscFlagsOff);
    out.pExtensions     = U32(p, kHdrExtensionsOff);
    out.ulTrackingStart = U32(p, kHdrTrackingStartOff);
    out.ulTrackingLen   = U32(p, kHdrTrackingLenOff);

    if (out.dllfirst > out.dlllast)   return false;
    if (out.physfirst > out.physlast) return false;
    if (out.nummods   > 10000)        return false;
    if (out.numfiles  > 50000)        return false;
    return true;
}

bool ParseSelfLocatingRomhdr(std::span<const uint8_t> xip,
                             uint32_t                 ptoc,
                             uint32_t                 physfirst,
                             ParsedROMHDR&            out) {
    if (physfirst > ptoc) return false;
    const size_t off = SelfLocatingRomhdrOffset(ptoc, physfirst);
    if (off + kRomHdrSize > xip.size()) return false;
    if (U32(xip.data(), off + kHdrPhysFirstOff) != physfirst) return false;
    return ParseRomHdr(xip, off, out);
}

template <typename BaseOf>
static bool ScanForRomhdr(std::span<const uint8_t> flat,
                          size_t                   start_off,
                          BaseOf                   base_of,
                          ParsedXipRegion&         out,
                          size_t&                  out_romhdr_off) {
    return ForEachParsedRomhdr(flat, start_off,
        [&](size_t off, const ParsedROMHDR& h) {
            uint32_t base = 0;
            if (!base_of(off, h, base)) return false;
            out.toc.romhdr    = h;
            out.toc.romhdr_va = base + uint32_t(off);
            out.load_offset   = base;
            out_romhdr_off    = off;
            return true;
        });
}

bool ResolveRomhdrAtEcec(std::span<const uint8_t> flat,
                         const EcecRecord&        ecec,
                         uint32_t                 flat_base_va,
                         ParsedXipRegion&         out,
                         size_t&                  out_romhdr_off) {
    const size_t   ecec_off = ecec.off;
    const uint32_t ev_ptoc  = ecec.ptoc;
    const uint32_t ev_off   = ecec.romhdr_off;

    struct Candidate { size_t romhdr_off; uint32_t load_offset; };
    std::vector<Candidate> candidates;
    auto add = [&](uint32_t cand_load) {
        if (ev_ptoc < cand_load) return;
        const uint32_t off = ev_ptoc - cand_load;
        for (const auto& c : candidates) {
            if (c.romhdr_off == off && c.load_offset == cand_load) return;
        }
        candidates.push_back({off, cand_load});
    };

    /* ECEC+8 is the ROMHDR offset from the XIP base when populated, but some
       BSPs leave it garbage (>=0x10000000); trusting it alone drops a region
       whose ECEC+8 is junk. Try it only when sane, then always run the
       candidate-base search (flat_base_va yields romhdr_off = ptoc - base). */
    if (ev_off && ev_off < 0x10000000u) {
        const size_t xip_base_off =
            (ecec_off >= kRomSignatureOffset) ? ecec_off - kRomSignatureOffset : 0;
        const size_t off = xip_base_off + ev_off;
        candidates.push_back({off, ev_ptoc - uint32_t(off)});
    }
    add(flat_base_va);
    add(flat_base_va | 0x80000000u);
    add(ev_ptoc & 0xFF000000u);
    add(ev_ptoc & 0xF0000000u);

    for (const auto& c : candidates) {
        if (!ParseRomHdr(flat, c.romhdr_off, out.toc.romhdr)) continue;
        if (!out.toc.romhdr.ImageContains(ev_ptoc)) continue;
        out.toc.romhdr_va = ev_ptoc;
        out.load_offset   = c.load_offset;
        out_romhdr_off    = c.romhdr_off;
        return true;
    }

    ParsedROMHDR h;
    uint32_t     physfirst = 0;
    if (!FindSelfLocatingRomhdr(
            flat, ev_ptoc, 4u, 0u,
            [&](const ParsedROMHDR& c) { return c.physlast - c.physfirst == flat.size(); },
            h, physfirst)) {
        return false;
    }
    out.toc.romhdr    = h;
    out.toc.romhdr_va = ev_ptoc;
    out.load_offset   = physfirst;
    out_romhdr_off    = SelfLocatingRomhdrOffset(ev_ptoc, physfirst);
    LOG(Boot, "RomImageParse: ECEC @ 0x%zX resolved by physfirst self-offset: "
              "ROMHDR @ flat 0x%zX physfirst=0x%08X\n",
        ecec_off, out_romhdr_off, physfirst);
    return true;
}

static bool StructuralTocNamesResolve(std::span<const uint8_t> flat,
                                      size_t                   romhdr_off,
                                      const ParsedROMHDR&      h,
                                      uint32_t                 name_base_va) {
    const size_t   toc_start = romhdr_off + kRomHdrSize;
    const uint32_t scan      = std::min<uint32_t>(h.nummods, 512);
    bool have_nk = false;
    for (uint32_t i = 0; i < scan; ++i) {
        const size_t e = toc_start + size_t(i) * kTocEntrySize;
        if (e + kTocEntrySize > flat.size()) return false;
        const uint32_t fname_va = U32(flat.data(), e + kTocOffFileName);
        if (fname_va < name_base_va) return false;
        const size_t fo = size_t(fname_va - name_base_va);
        if (fo >= flat.size()) return false;
        const std::string name = ReadAsciiZ(flat, fo);
        if (name.empty()) return false;
        for (char c : name) {
            if (uint8_t(c) < 0x20 || uint8_t(c) > 0x7E) return false;
        }
        if (name.size() == 6
            && (name[0] | 0x20) == 'n' && (name[1] | 0x20) == 'k'
            && name[2] == '.'
            && (name[3] | 0x20) == 'e' && (name[4] | 0x20) == 'x'
            && (name[5] | 0x20) == 'e') {
            have_nk = true;
        }
    }
    return have_nk;
}

bool ResolveRomhdrStructural(std::span<const uint8_t> flat,
                             ParsedXipRegion&         out,
                             size_t&                  out_romhdr_off) {
    return ScanForRomhdr(
        flat, 0,
        [&](size_t off, const ParsedROMHDR& h, uint32_t& base) {
            if (h.nummods == 0) return false;
            if (!StructuralTocNamesResolve(flat, off, h, h.physfirst)) return false;
            base = h.physfirst;
            return true;
        },
        out, out_romhdr_off);
}

bool ResolveNextStructuralXip(std::span<const uint8_t> flat,
                              size_t                   start_off,
                              uint32_t                 flat_base_va,
                              ParsedXipRegion&         out,
                              size_t&                  out_romhdr_off) {
    return ScanForRomhdr(
        flat, start_off,
        [&](size_t off, const ParsedROMHDR& h, uint32_t& base) {
            if (h.nummods == 0) return false;
            const uint32_t romhdr_va = flat_base_va + uint32_t(off);
            if (!h.ImageContains(romhdr_va)) return false;
            if (!StructuralTocNamesResolve(flat, off, h, flat_base_va)) return false;
            base = flat_base_va;
            return true;
        },
        out, out_romhdr_off);
}

void ParseModulesAndFiles(std::span<const uint8_t> flat,
                          size_t                   romhdr_off,
                          uint32_t                 load_offset,
                          const ParsedROMHDR&      h,
                          ParsedTOC&               toc) {
    const size_t toc_start   = romhdr_off + kRomHdrSize;
    const size_t files_start = toc_start + h.nummods * kTocEntrySize;

    toc.modules.reserve(h.nummods);
    for (uint32_t i = 0; i < h.nummods; ++i) {
        const size_t entry_off = toc_start + i * kTocEntrySize;
        if (entry_off + kTocEntrySize > flat.size()) break;
        const uint8_t* e = flat.data() + entry_off;
        ParsedTOCentry m;
        m.dwFileAttributes = U32(e, kTocOffAttributes);
        m.ftTime           = (uint64_t(U32(e, kTocOffTimeHigh)) << 32) | U32(e, kTocOffTimeLow);
        m.nFileSize        = U32(e, kTocOffNFileSize);
        const uint32_t fname_va = U32(e, kTocOffFileName);
        m.ulE32Offset      = U32(e, kTocOffE32Offset);
        m.ulO32Offset      = U32(e, kTocOffO32Offset);
        m.ulLoadOffset     = U32(e, kTocOffLoadOffset);
        if (fname_va >= load_offset) {
            const size_t fname_foff = size_t(fname_va - load_offset);
            if (fname_foff < flat.size())
                m.lpszFileName = ReadAsciiZ(flat, fname_foff);
        }
        toc.modules.push_back(std::move(m));
    }

    toc.files.reserve(h.numfiles);
    for (uint32_t i = 0; i < h.numfiles; ++i) {
        const size_t entry_off = files_start + i * kFileEntrySize;
        if (entry_off + kFileEntrySize > flat.size()) break;
        const uint8_t* e = flat.data() + entry_off;
        ParsedFILESentry f;
        f.dwFileAttributes = U32(e, kFileOffAttributes);
        f.ftTime           = (uint64_t(U32(e, kFileOffTimeHigh)) << 32) | U32(e, kFileOffTimeLow);
        f.nRealFileSize    = U32(e, kFileOffRealSize);
        f.nCompFileSize    = U32(e, kFileOffCompSize);
        const uint32_t fname_va = U32(e, kFileOffFileName);
        f.ulLoadOffset     = U32(e, kFileOffLoadOffset);
        if (fname_va >= load_offset) {
            const size_t fname_foff = size_t(fname_va - load_offset);
            if (fname_foff < flat.size())
                f.lpszFileName = ReadAsciiZ(flat, fname_foff);
        }
        toc.files.push_back(std::move(f));
    }
}

bool ReadImgfsSuperblock(std::span<const uint8_t> bytes, size_t off, ImgfsSuperblock& out) {
    if (off + kImgfsSbSize > bytes.size()) return false;
    if (std::memcmp(bytes.data() + off, kImgfsUuid, sizeof(kImgfsUuid)) != 0) return false;
    out.off             = off;
    out.dirent_size     = U32(bytes.data(), off + kImgfsSbOffDirentSize);
    out.bytes_per_block = U32(bytes.data(), off + kImgfsSbOffBytesPerBlock);
    return true;
}

bool FindImgfsBase(std::span<const uint8_t> raw, ImgfsSuperblock& out) {
    for (size_t pos = 0; pos < raw.size(); pos += 0x1000) {
        ImgfsSuperblock sb;
        if (!ReadImgfsSuperblock(raw, pos, sb)) continue;
        if (sb.dirent_size != kImgfsDirentSize) continue;
        if (sb.bytes_per_block < 0x200 || sb.bytes_per_block > 0x10000) continue;
        out = sb;
        return true;
    }
    return false;
}

}  /* namespace cerf::rom_image_parse */
