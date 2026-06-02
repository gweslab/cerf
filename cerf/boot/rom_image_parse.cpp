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

bool AssembleB000FFFlat(const std::vector<uint8_t>& raw,
                        std::vector<uint8_t>& out_flat,
                        uint32_t& out_base_va,
                        uint32_t& out_entry_va) {
    if (raw.size() < 15) return false;
    if (std::memcmp(raw.data(), kB000FFSignature, 7) != 0) return false;

    struct Section { uint32_t base; uint32_t size; size_t data_off; };
    std::vector<Section> sections;
    out_entry_va = 0;

    size_t off = 15;  /* sig (7) + image start (4) + image length (4) */
    while (off + kB000FFSectionHeaderSize <= raw.size()) {
        uint32_t base = U32(raw.data(), off);
        uint32_t size = U32(raw.data(), off + 4);
        /* checksum at off+8 — ignored. */
        if (base == 0) {
            /* Terminator section (base=0): the loader convention
               reuses the section header's 'size' field as the kernel
               entry-point VA — the only place B000FF encodes where
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

std::vector<size_t> FindAllEcec(std::span<const uint8_t> flat) {
    std::vector<size_t> out;
    const size_t limit = std::min<size_t>(flat.size(), 0x800000);
    for (size_t i = 0; i + 12 <= limit; ++i) {
        if (U32(flat.data(), i) != kRomSignature) continue;
        const uint32_t ptoc_va    = U32(flat.data(), i + 4);
        const uint32_t romhdr_off = U32(flat.data(), i + 8);
        if (ptoc_va >= 0x80000000u && ptoc_va < 0xC0000000u
            && romhdr_off < 0x10000000u) {
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

    if (ev_off) {
        /* ECEC+8 (ROM_TOC_OFFSET_OFFSET) — explicit byte offset of the
           ROMHDR relative to the XIP region's base in the file. CE5+ /
           WM5+ always populate this. The XIP's file-base is the ECEC
           marker minus 0x40 (ROM_SIGNATURE_OFFSET). */
        const size_t xip_base_off =
            (ecec_off >= kRomSignatureOffset) ? ecec_off - kRomSignatureOffset : 0;
        const size_t off = xip_base_off + ev_off;
        candidates.push_back({off, ev_ptoc - uint32_t(off)});
    } else {
        /* CE3 leaves ECEC+8 zero — fall back to candidate-base search. */
        add(flat_base_va);
        add(flat_base_va | 0x80000000u);
        add(ev_ptoc & 0xFF000000u);
        add(ev_ptoc & 0xF0000000u);
    }

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

bool ResolveRomhdrStructural(std::span<const uint8_t> flat,
                             ParsedXipRegion&         out,
                             size_t&                  out_romhdr_off) {
    for (size_t off = 0; off + kRomHdrSize <= flat.size(); off += 4) {
        ParsedROMHDR h;
        if (!ParseRomHdr(flat, off, h)) continue;
        if (h.nummods == 0) continue;

        const uint32_t load_offset = h.physfirst;
        const size_t   toc_start   = off + kRomHdrSize;
        const uint32_t scan        = std::min<uint32_t>(h.nummods, 512);

        bool names_ok = true;
        bool have_nk  = false;
        for (uint32_t i = 0; i < scan && names_ok; ++i) {
            const size_t e = toc_start + size_t(i) * kTocEntrySize;
            if (e + kTocEntrySize > flat.size()) { names_ok = false; break; }
            const uint32_t fname_va = U32(flat.data(), e + 0x10);
            if (fname_va < load_offset) { names_ok = false; break; }
            const size_t fo = size_t(fname_va - load_offset);
            if (fo >= flat.size()) { names_ok = false; break; }
            const std::string name = ReadAsciiZ(flat, fo);
            if (name.empty()) { names_ok = false; break; }
            for (char c : name) {
                if (uint8_t(c) < 0x20 || uint8_t(c) > 0x7E) {
                    names_ok = false;
                    break;
                }
            }
            if (names_ok && name.size() == 6
                && (name[0] | 0x20) == 'n' && (name[1] | 0x20) == 'k'
                && name[2] == '.'
                && (name[3] | 0x20) == 'e' && (name[4] | 0x20) == 'x'
                && (name[5] | 0x20) == 'e') {
                have_nk = true;
            }
        }
        if (!names_ok || !have_nk) continue;

        out.toc.romhdr    = h;
        out.toc.romhdr_va = load_offset + uint32_t(off);
        out.load_offset   = load_offset;
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
       validate the header fields. Port of imgfs.py::find_imgfs_base —
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
