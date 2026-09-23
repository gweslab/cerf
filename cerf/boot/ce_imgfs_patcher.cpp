#include "ce_imgfs_patcher.h"

#include "pe_image.h"

#include "../core/byte_order.h"

#include <algorithm>
#include <cstring>

namespace cerf::ce_imgfs_patcher {

namespace {

using cerf::le::Put16;
using cerf::le::Put32;

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
    return BuildIndexBlock(std::vector<IndexRec>{{data_size, data_logical_addr}});
}

std::vector<uint8_t> BuildIndexBlock(const std::vector<IndexRec>& records) {
    using namespace cerf::ce_imgfs_walker;
    std::vector<uint8_t> idx((records.size() + 1) * kIndexRecSize, 0);
    for (size_t i = 0; i < records.size(); ++i) {
        uint8_t* const rec = idx.data() + i * kIndexRecSize;
        Put16(rec + kIndexRecOffCompSize, uint16_t(records[i].data_size));
        Put16(rec + kIndexRecOffFullSize, uint16_t(records[i].data_size));
        Put32(rec + kIndexRecOffPtr, records[i].data_logical_addr);
    }
    return idx;
}

std::vector<uint8_t> BuildModuleHeader(const PeImage&              pe,
                                        uint32_t                    target_vbase,
                                        uint16_t                    subsys_major,
                                        uint16_t                    subsys_minor,
                                        const std::vector<uint32_t>& slot_realaddr,
                                        const std::vector<PackedSlot>& slots) {
    const size_t header_size = kE32RomCE5plusO32Base + slots.size() * kO32RomSize;
    std::vector<uint8_t> hdr(header_size, 0);
    uint8_t* const h = hdr.data();
    const E32RomLayout& L = kE32RomCE5plus;

    Put16(h + L.off_objcnt,      uint16_t(slots.size()));
    Put16(h + L.off_imageflags,  pe.ImageFlags());
    Put32(h + L.off_entryrva,    pe.EntryRva());
    Put32(h + L.off_vbase,       target_vbase);
    Put16(h + L.off_subsysmajor, subsys_major);
    Put16(h + L.off_subsysminor, subsys_minor);
    Put32(h + L.off_stackmax,   pe.StackReserve());
    Put32(h + L.off_vsize,      pe.ImageSize());
    Put32(h + L.off_sect14rva,  0);
    Put32(h + L.off_sect14size, 0);
    Put32(h + L.off_timestamp,  0);
    for (int i = 0; i < kE32UnitCount; ++i) {
        Put32(h + L.off_unit + uint32_t(i) * 8u + 0, pe.DirRva (i));
        Put32(h + L.off_unit + uint32_t(i) * 8u + 4, pe.DirSize(i));
    }
    Put16(h + L.off_subsys, pe.Subsystem());

    for (size_t i = 0; i < slots.size(); ++i) {
        const auto& s = slots[i];
        uint8_t* const o32 = h + kE32RomCE5plusO32Base + i * kO32RomSize;
        Put32(o32 + kO32OffVsize,    s.vsize);
        Put32(o32 + kO32OffRva,      s.rva);
        Put32(o32 + kO32OffPsize,    s.psize);
        Put32(o32 + kO32OffDataptr,  uint32_t(i) << 28);
        Put32(o32 + kO32OffRealaddr, slot_realaddr[i]);
        Put32(o32 + kO32OffFlags,    s.flags);
    }
    return hdr;
}

}
