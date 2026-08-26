#define NOMINMAX

#include "rom_image_parse.h"

#include "../core/log.h"

#include <algorithm>
#include <cstring>

namespace cerf::rom_image_parse {

namespace {

std::string ReadAsciiZ(std::span<const uint8_t> flat, size_t off) {
    std::string s;
    while (off < flat.size() && flat[off] != 0) {
        s.push_back(char(flat[off]));
        ++off;
    }
    return s;
}

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

    /* ECEC at XIP+0x40 -> ROMHDR kernel-VA. */
    if (xip + kRomSignatureOffset + 8 > raw.size()) return false;
    if (U32(raw.data(), xip + kRomSignatureOffset) != kRomSignature) return false;
    const uint32_t ev_ptoc = U32(raw.data(), xip + kRomSignatureOffset + 4);

    /* The image can cross a 16 MB boundary, so ev_ptoc's high byte is not
       necessarily physfirst's - try the 16 MB-aligned bases at/below ev_ptoc and
       accept the one whose ROMHDR self-validates. */
    constexpr uint32_t kWindowGrain = 0x01000000u;
    const uint32_t top   = ev_ptoc & ~(kWindowGrain - 1u);
    const uint32_t steps = (span / kWindowGrain) + 2u;
    for (uint32_t i = 0; i <= steps && i < 16u; ++i) {
        if (top < i * kWindowGrain) break;
        const uint32_t base = top - i * kWindowGrain;
        const uint32_t pf   = base + pf_off;
        if (pf > ev_ptoc || ev_ptoc - pf >= span) continue;
        const size_t romhdr_off = xip + (ev_ptoc - pf);
        ParsedROMHDR h;
        if (!ParseRomHdr(raw, romhdr_off, h)) continue;
        if (h.physfirst != pf || h.physlast - h.physfirst != span) continue;
        out.data_off  = xip;
        out.flat_size = span;
        out.base_va   = pf;
        out.entry_va  = pf + (en_off - pf_off);
        return true;
    }
    return false;
}

size_t FindXipEcec(std::span<const uint8_t> raw, size_t start) {
    for (size_t i = start; i + 8 <= raw.size(); ++i) {
        if (U32(raw.data(), i) != kRomSignature) continue;
        const uint32_t ptoc = U32(raw.data(), i + 4);
        if (ptoc >= 0x80000000u && ptoc < 0xC0000000u) return i;
    }
    return SIZE_MAX;
}

bool ArnoldLocateOsXip(std::span<const uint8_t> raw, ArnoldOsXip& out) {
    if (raw.size() < sizeof(kArnoldSignature) + kRomSignatureOffset + 8)
        return false;
    if (std::memcmp(raw.data(), kArnoldSignature, sizeof(kArnoldSignature)) != 0)
        return false;

    const size_t ecec = FindXipEcec(raw, sizeof(kArnoldSignature));
    if (ecec == SIZE_MAX || ecec < kRomSignatureOffset) return false;

    const size_t   data_off = ecec - kRomSignatureOffset;
    const uint32_t ev_ptoc  = U32(raw.data(), ecec + 4);
    const size_t   xip_size = raw.size() - data_off;
    std::span<const uint8_t> xip = raw.subspan(data_off);

    /* base_va == ROMHDR.physfirst, and the ROMHDR sits at XIP offset
       (ev_ptoc - base_va). ARNOLD leaves ECEC+8 (the ROMHDR offset) zero, so the
       base is recovered by scanning page-aligned candidates and accepting the one
       whose ROMHDR.physfirst equals the candidate base. */
    const uint32_t base_top = ev_ptoc & ~0xFFFu;
    const uint32_t base_min =
        (ev_ptoc > uint32_t(xip_size)) ? ev_ptoc - uint32_t(xip_size) : 0u;
    for (uint32_t base = base_top; base >= base_min; base -= 0x1000u) {
        const uint32_t romhdr_off = ev_ptoc - base;
        if (romhdr_off + kRomHdrSize <= xip_size) {
            ParsedROMHDR h;
            if (ParseRomHdr(xip, romhdr_off, h) && h.physfirst == base) {
                out.data_off  = data_off;
                out.flat_size = uint32_t(xip_size);
                out.base_va   = base;
                return true;
            }
        }
        if (base < base_min + 0x1000u) break;  /* guard unsigned wrap past base_min */
    }
    return false;
}

bool IpaqNbfLocateOsXip(std::span<const uint8_t> raw, IpaqNbfOsXip& out) {
    if (raw.size() < sizeof(kIpaqNbfSignature) + kRomSignatureOffset + 8)
        return false;
    if (std::memcmp(raw.data(), kIpaqNbfSignature, sizeof(kIpaqNbfSignature)) != 0)
        return false;

    /* The banner is followed by a raw flat XIP carrying 'ECEC' at XIP+0x40; the
       first marker with a kernel-VA pTOC locates the XIP regardless of banner
       length. The base VA is left for the shared ECEC resolver, identical to a
       raw .nb0. */
    const size_t ecec = FindXipEcec(raw, sizeof(kIpaqNbfSignature));
    if (ecec == SIZE_MAX || ecec < kRomSignatureOffset) return false;

    out.data_off  = ecec - kRomSignatureOffset;
    out.flat_size = uint32_t(raw.size() - out.data_off);
    return true;
}

std::vector<size_t> FindAllEcec(std::span<const uint8_t> flat) {
    std::vector<size_t> out;
    /* Scan the whole flat - a multi-XIP ROM keeps the NK kernel region in the
       file tail, far past any front window; a size cap drops that region and
       the kernel never gets placed. Each hit is validated by ParseRomHdr
       downstream, so a stray 'ECEC' byte match costs nothing. */
    for (size_t i = 0; i + 12 <= flat.size(); ++i) {
        if (U32(flat.data(), i) != kRomSignature) continue;
        const uint32_t ptoc_va = U32(flat.data(), i + 4);
        /* Gate on the ROMHDR VA only: ECEC+8 is an optional offset some BSPs
           leave as garbage (NEC P530: 0xE1001D28), so requiring it small
           rejects valid regions. */
        if (ptoc_va >= 0x80000000u && ptoc_va < 0xC0000000u) {
            out.push_back(i);
        }
    }
    return out;
}

bool ParseRomHdr(std::span<const uint8_t> flat, size_t off, ParsedROMHDR& out) {
    if (off + kRomHdrSize > flat.size()) return false;
    const uint8_t* p = flat.data() + off;
    out.dllfirst        = U32(p, 0x00);
    out.dlllast         = U32(p, 0x04);
    out.physfirst       = U32(p, 0x08);
    out.physlast        = U32(p, 0x0C);
    out.nummods         = U32(p, 0x10);
    out.ulRAMStart      = U32(p, 0x14);
    out.ulRAMFree       = U32(p, 0x18);
    out.ulRAMEnd        = U32(p, 0x1C);
    out.ulCopyEntries   = U32(p, 0x20);
    out.ulCopyOffset    = U32(p, 0x24);
    out.ulProfileLen    = U32(p, 0x28);
    out.ulProfileOffset = U32(p, 0x2C);
    out.numfiles        = U32(p, 0x30);
    out.ulKernelFlags   = U32(p, 0x34);
    out.ulFSRamPercent  = U32(p, 0x38);
    out.ulDrivglobStart = U32(p, 0x3C);
    out.ulDrivglobLen   = U32(p, 0x40);
    out.usCPUType       = U16(p, 0x44);
    out.usMiscFlags     = U16(p, 0x46);
    out.pExtensions     = U32(p, 0x48);
    out.ulTrackingStart = U32(p, 0x4C);
    out.ulTrackingLen   = U32(p, 0x50);

    if (out.dllfirst > out.dlllast)   return false;
    if (out.physfirst > out.physlast) return false;
    if (out.nummods   > 10000)        return false;
    if (out.numfiles  > 50000)        return false;
    return true;
}

bool ResolveRomhdrAtEcec(std::span<const uint8_t> flat,
                         size_t                   ecec_off,
                         uint32_t                 flat_base_va,
                         ParsedXipRegion&         out,
                         size_t&                  out_romhdr_off) {
    const uint32_t ev_ptoc = U32(flat.data(), ecec_off + 4);
    const uint32_t ev_off  = U32(flat.data(), ecec_off + 8);

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
        if (c.romhdr_off + kRomHdrSize > flat.size()) continue;
        if (!ParseRomHdr(flat, c.romhdr_off, out.toc.romhdr)) continue;
        out.toc.romhdr_va = ev_ptoc;
        out.load_offset   = c.load_offset;
        out_romhdr_off    = c.romhdr_off;
        return true;
    }

    return false;
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
        const uint32_t fname_va = U32(flat.data(), e + 0x10);
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
    for (size_t off = 0; off + kRomHdrSize <= flat.size(); off += 4) {
        ParsedROMHDR h;
        if (!ParseRomHdr(flat, off, h)) continue;
        if (h.nummods == 0) continue;
        if (!StructuralTocNamesResolve(flat, off, h, h.physfirst)) continue;

        out.toc.romhdr    = h;
        out.toc.romhdr_va = h.physfirst + uint32_t(off);
        out.load_offset   = h.physfirst;
        out_romhdr_off    = off;
        return true;
    }
    return false;
}

bool ResolveNextStructuralXip(std::span<const uint8_t> flat,
                              size_t                   start_off,
                              uint32_t                 flat_base_va,
                              ParsedXipRegion&         out,
                              size_t&                  out_romhdr_off) {
    for (size_t off = start_off; off + kRomHdrSize <= flat.size(); off += 4) {
        ParsedROMHDR h;
        if (!ParseRomHdr(flat, off, h)) continue;
        if (h.nummods == 0) continue;

        const uint32_t romhdr_va = flat_base_va + uint32_t(off);
        if (romhdr_va < h.physfirst || romhdr_va >= h.physlast) continue;
        if (!StructuralTocNamesResolve(flat, off, h, flat_base_va)) continue;

        out.toc.romhdr    = h;
        out.toc.romhdr_va = romhdr_va;
        out.load_offset   = flat_base_va;
        out_romhdr_off    = off;
        return true;
    }
    return false;
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
        m.dwFileAttributes = U32(e, 0x00);
        m.ftTime           = (uint64_t(U32(e, 0x08)) << 32) | U32(e, 0x04);
        m.nFileSize        = U32(e, 0x0C);
        const uint32_t fname_va = U32(e, 0x10);
        m.ulE32Offset      = U32(e, 0x14);
        m.ulO32Offset      = U32(e, 0x18);
        m.ulLoadOffset     = U32(e, 0x1C);
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
        f.dwFileAttributes = U32(e, 0x00);
        f.ftTime           = (uint64_t(U32(e, 0x08)) << 32) | U32(e, 0x04);
        f.nRealFileSize    = U32(e, 0x0C);
        f.nCompFileSize    = U32(e, 0x10);
        const uint32_t fname_va = U32(e, 0x14);
        f.ulLoadOffset     = U32(e, 0x18);
        if (fname_va >= load_offset) {
            const size_t fname_foff = size_t(fname_va - load_offset);
            if (fname_foff < flat.size())
                f.lpszFileName = ReadAsciiZ(flat, fname_foff);
        }
        toc.files.push_back(std::move(f));
    }
}

size_t FindImgfsBase(std::span<const uint8_t> raw) {
    /* Scan for the IMGFS superblock UUID at page-aligned offsets and
       validate the header fields. Port of imgfs.py::find_imgfs_base -
       check `dirent_size` at +0x1C and a sane `bytes_per_block` at
       +0x24 (0x200..0x10000). */
    size_t pos = 0;
    while (pos + sizeof(kImgfsUuid) <= raw.size()) {
        bool match = std::memcmp(raw.data() + pos, kImgfsUuid,
                                 sizeof(kImgfsUuid)) == 0;
        if (match && (pos & 0xFFFu) == 0 && pos + 0x28 <= raw.size()) {
            const uint32_t ds  = U32(raw.data(), pos + 0x1C);
            const uint32_t bpb = U32(raw.data(), pos + 0x24);
            if (ds == kImgfsDirentSize && bpb >= 0x200 && bpb <= 0x10000) {
                return pos;
            }
        }
        ++pos;
    }
    return SIZE_MAX;
}

}  /* namespace cerf::rom_image_parse */
