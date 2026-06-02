#include "ce_imgfs_patcher.h"

#include "pe_image.h"

#include <algorithm>
#include <cstring>

namespace cerf::ce_imgfs_patcher {

namespace {

constexpr int kE32UnitCount = 9;
constexpr uint32_t kO32RomSize = 24;
constexpr uint32_t kHeaderO32Base = 0x70;

inline void Wr16(std::vector<uint8_t>& v, size_t off, uint16_t x) {
    v[off]     = uint8_t(x);
    v[off + 1] = uint8_t(x >> 8);
}
inline void Wr32(std::vector<uint8_t>& v, size_t off, uint32_t x) {
    v[off]     = uint8_t(x);
    v[off + 1] = uint8_t(x >> 8);
    v[off + 2] = uint8_t(x >> 16);
    v[off + 3] = uint8_t(x >> 24);
}

}

std::vector<PackedSlot> PackPeSections(const PeImage&             pe,
                                        const std::vector<uint8_t>& pe_bytes,
                                        size_t                     target_slot_count) {
    std::vector<PackedSlot> slots;
    const auto& sections = pe.Sections();
    if (sections.empty() || target_slot_count == 0) return slots;

    const size_t N = sections.size();
    const size_t K = std::min(target_slot_count, N);

    std::vector<std::pair<size_t, size_t>> groups;
    groups.reserve(K);
    if (N == K) {
        for (size_t i = 0; i < K; ++i) groups.push_back({i, i});
    } else {
        for (size_t i = 0; i + 1 < K; ++i) groups.push_back({i, i});
        groups.push_back({K - 1, N - 1});
    }

    slots.reserve(K);
    for (const auto& g : groups) {
        const auto& first = sections[g.first];
        const auto& last  = sections[g.second];
        PackedSlot s;
        s.rva   = first.rva;
        s.vsize = (last.rva + last.vsize) - first.rva;
        s.flags = 0;
        for (size_t i = g.first; i <= g.second; ++i) s.flags |= sections[i].flags;

        s.bytes.assign(s.vsize, 0);
        for (size_t i = g.first; i <= g.second; ++i) {
            const auto& sec = sections[i];
            const size_t off_in_slot = sec.rva - s.rva;
            const uint32_t copy_n = std::min(sec.psize, sec.vsize);
            if (copy_n == 0) continue;
            if (size_t(sec.pe_file_off) + copy_n > pe_bytes.size()) continue;
            if (off_in_slot + copy_n > s.bytes.size()) continue;
            std::memcpy(s.bytes.data() + off_in_slot,
                        pe_bytes.data() + sec.pe_file_off,
                        copy_n);
        }
        s.psize = uint32_t(s.bytes.size());
        slots.push_back(std::move(s));
    }
    return slots;
}

std::vector<uint8_t> BuildIndexBlock(uint32_t data_size,
                                      uint32_t data_logical_addr) {
    std::vector<uint8_t> idx(16, 0);
    Wr16(idx,  0, uint16_t(data_size));
    Wr16(idx,  2, uint16_t(data_size));
    Wr32(idx,  4, data_logical_addr);
    return idx;
}

std::vector<uint8_t> BuildIndexBlock(const std::vector<IndexRec>& records) {
    std::vector<uint8_t> idx((records.size() + 1) * 8, 0);
    for (size_t i = 0; i < records.size(); ++i) {
        const size_t base = i * 8;
        Wr16(idx, base + 0, uint16_t(records[i].data_size));
        Wr16(idx, base + 2, uint16_t(records[i].data_size));
        Wr32(idx, base + 4, records[i].data_logical_addr);
    }
    return idx;
}

std::vector<uint8_t> BuildModuleHeader(const E32Layout&             L,
                                        const PeImage&              pe,
                                        uint32_t                    target_vbase,
                                        const std::vector<PackedSlot>& slots) {
    const size_t header_size = kHeaderO32Base + slots.size() * kO32RomSize;
    std::vector<uint8_t> hdr(header_size, 0);

    Wr16(hdr, L.off_objcnt,      uint16_t(slots.size()));
    Wr16(hdr, L.off_imageflags,  pe.ImageFlags());
    Wr32(hdr, L.off_entryrva,    pe.EntryRva());
    Wr32(hdr, L.off_vbase,       target_vbase);
    Wr16(hdr, L.off_subsysmajor, pe.SubsysMajor());
    Wr16(hdr, L.off_subsysminor, pe.SubsysMinor());
    Wr32(hdr, L.off_stackmax,    pe.StackReserve());
    Wr32(hdr, L.off_vsize,       pe.ImageSize());
    Wr32(hdr, L.off_sect14rva,   0);
    Wr32(hdr, L.off_sect14size,  0);
    if (L.off_timestamp >= 0) {
        Wr32(hdr, uint32_t(L.off_timestamp), 0);
    }
    for (int i = 0; i < kE32UnitCount; ++i) {
        Wr32(hdr, L.off_unit + uint32_t(i) * 8u + 0, pe.DirRva (i));
        Wr32(hdr, L.off_unit + uint32_t(i) * 8u + 4, pe.DirSize(i));
    }
    Wr16(hdr, L.off_subsys, pe.Subsystem());

    for (size_t i = 0; i < slots.size(); ++i) {
        const auto& s = slots[i];
        const size_t base = kHeaderO32Base + i * kO32RomSize;
        Wr32(hdr, base + 0,  s.vsize);
        Wr32(hdr, base + 4,  s.rva);
        Wr32(hdr, base + 8,  s.psize);
        Wr32(hdr, base + 12, uint32_t(i) << 28);   /* dataptr */
        Wr32(hdr, base + 16, target_vbase + s.rva); /* realaddr */
        Wr32(hdr, base + 20, s.flags);
    }
    return hdr;
}

}
