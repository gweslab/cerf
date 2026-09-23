#define _CRT_SECURE_NO_WARNINGS

#include "imgfs_victim_recomposer.h"

#include "ce_image_relocator.h"
#include "guest_additions_binaries.h"
#include "guest_module_placer.h"
#include "pe_image.h"
#include "rom_record_layout.h"

#include "../core/byte_order.h"
#include "../core/cerf_emulator.h"
#include "../core/log.h"

#include <fstream>

REGISTER_SERVICE(ImgfsVictimRecomposer);

namespace {

using cerf::le::U16;
using cerf::le::U32;

}  // namespace

std::optional<ImgfsVictimRecomposer::Result>
ImgfsVictimRecomposer::Recompose(std::span<const uint8_t> orig_hdr,
                                 size_t                    num_sections,
                                 const std::string&        stub_path) {
    if (orig_hdr.size() < kE32RomCE5plusO32Base) {
        LOG(Caution, "[GA recompose] victim header too short (%zu bytes)\n",
            orig_hdr.size());
        return std::nullopt;
    }
    const uint8_t* h = orig_hdr.data();
    const uint32_t orig_vbase     = U32(h, kE32OffVbase);
    const uint16_t orig_objcnt    = U16(h, kE32OffObjcnt);
    const uint16_t orig_subsysmaj = U16(h, kE32OffSubsysMajor);
    const uint16_t orig_subsysmin = U16(h, kE32OffSubsysMinor);
    if (orig_objcnt == 0
        || size_t(kE32RomCE5plusO32Base) + size_t(orig_objcnt) * kO32RomSize > orig_hdr.size()) {
        LOG(Caution, "[GA recompose] victim objcnt=%u inconsistent with header "
            "size %zu\n", orig_objcnt, orig_hdr.size());
        return std::nullopt;
    }
    const uint32_t orig_realaddr0 = U32(h, kE32RomCE5plusO32Base + kO32OffRealaddr);
    const uint32_t orig_rva0      = U32(h, kE32RomCE5plusO32Base + kO32OffRva);
    const uint32_t slot_base = orig_realaddr0 - orig_rva0 - orig_vbase;

    std::ifstream f(stub_path, std::ios::binary | std::ios::ate);
    if (!f.is_open()) {
        LOG(Caution, "[GA recompose] cannot open stub %s\n", stub_path.c_str());
        CerfFatalExit();
    }
    const auto sz = f.tellg();
    std::vector<uint8_t> pe_bytes(static_cast<size_t>(sz));
    f.seekg(0);
    f.read(reinterpret_cast<char*>(pe_bytes.data()), sz);
    PeImage pe(std::move(pe_bytes));
    if (!pe.Parsed()) {
        LOG(Caution, "[GA recompose] stub PE parse failed (%s)\n", stub_path.c_str());
        CerfFatalExit();
    }

    std::vector<uint32_t> section_realaddr(pe.Sections().size());
    for (size_t i = 0; i < pe.Sections().size(); ++i)
        section_realaddr[i] = orig_vbase + slot_base + pe.Sections()[i].rva;

    std::vector<uint8_t> reloc_bytes(pe.Bytes().begin(), pe.Bytes().end());
    const int32_t code_delta = int32_t(orig_vbase) - int32_t(pe.ImageBase());
    uint32_t reloc_count = 0, unhandled = 0;
    cerf::ce_image_relocator::ApplyRelocations(
        reloc_bytes, pe, section_realaddr, code_delta, reloc_count, unhandled);
    if (unhandled > 0) {
        LOG(Caution, "[GA recompose] %u unhandled relocations in stub\n", unhandled);
        CerfFatalExit();
    }

    emu_.Get<GuestAdditionsBinaries>().StampWindowBase(reloc_bytes);

    auto slots = cerf::ce_imgfs_patcher::PackPeSections(pe, reloc_bytes, num_sections);
    if (slots.empty() || slots.size() > num_sections) {
        LOG(Caution, "[GA recompose] packing yielded %zu slots (victim sections=%zu)\n",
            slots.size(), num_sections);
        return std::nullopt;
    }
    auto& placer = emu_.Get<GuestModulePlacer>();
    for (auto& s : slots) s.flags = placer.EffSectionFlags(s.flags);

    std::vector<uint32_t> slot_realaddr;
    slot_realaddr.reserve(slots.size());
    for (const auto& s : slots) slot_realaddr.push_back(orig_vbase + slot_base + s.rva);
    auto new_hdr = cerf::ce_imgfs_patcher::BuildModuleHeader(
        pe, orig_vbase, orig_subsysmaj, orig_subsysmin,
        slot_realaddr, slots);

    LOG(GuestAdditions, "[GA recompose] vbase=0x%08X subsysver=%u.%02u slots=%zu "
        "hdr=%zu reloc=%u\n",
        orig_vbase, orig_subsysmaj, orig_subsysmin, slots.size(),
        new_hdr.size(), reloc_count);
    return Result{std::move(new_hdr), std::move(slots)};
}
