#define NOMINMAX

#include "guest_module_placer.h"

#include "rom_parser_service.h"
#include "rom_record_layout.h"

#include "../core/cerf_emulator.h"
#include "../core/log.h"
#include "../cpu/emulated_memory.h"
#include "../boards/page_table_builder.h"

REGISTER_SERVICE(GuestModulePlacer);

namespace {

constexpr uint32_t kModCodeBase  = 0x02000000u;
constexpr uint32_t kModCodeEnd   = 0x04000000u;
constexpr uint32_t kDllSlotAlign = 0x10000u;   /* XIP DLL 64K slot alignment */

}  /* namespace */

uint32_t GuestModulePlacer::EffSectionFlags(uint32_t flags) const {
    constexpr uint32_t kImgScnMemShared = 0x10000000u;
    constexpr uint32_t kImgScnMemWrite  = 0x80000000u;
    return (flags & kImgScnMemWrite) ? (flags | kImgScnMemShared) : flags;
}

uint32_t GuestModulePlacer::ComputeVbase(uint32_t orig_vbase,
                                          uint32_t orig_slot_base,
                                          uint32_t image_size,
                                          uint32_t ce_major,
                                          uint32_t e32_off_vbase,
                                          const char* victim_name) {
    auto& parser = emu_.Get<RomParserService>();
    auto& pt  = emu_.Get<PageTableBuilder>();
    auto& mem = emu_.Get<EmulatedMemory>();
    const auto& toc = parser.Primary().xips[0].toc;

    uint32_t slot_ceiling = 0xFFFFFFFFu;   /* lowest module vbase > victim */
    uint32_t lowest_code  = 0xFFFFFFFFu;   /* lowest section-1 code realaddr */
    for (const auto& m : toc.modules) {
        const uint32_t e32_pa = pt.VaToPa(m.ulE32Offset);
        if (e32_pa) {
            const uint32_t vb = mem.ReadWord(e32_pa + e32_off_vbase);
            if (vb && vb > orig_vbase && vb < slot_ceiling) slot_ceiling = vb;
        }
        const uint32_t o32_pa = pt.VaToPa(m.ulO32Offset);
        if (o32_pa) {
            const uint32_t code = mem.ReadWord(o32_pa + kO32OffRealaddr);
            if (code >= kModCodeBase && code < kModCodeEnd && code < lowest_code)
                lowest_code = code;
        }
    }
    const uint32_t slot = (slot_ceiling == 0xFFFFFFFFu)
                        ? 0xFFFFFFFFu : (slot_ceiling - orig_vbase);

    /* Relocate on EITHER trigger: slot overflow, OR a section-0 codebase - a
       runtime-loaded ROM DLL must live in section 1 (SharedDllBase-covered);
       dropping the section-0 test regresses CE4.2/WM5 (codebase 0x01xxxxxx). */
    const uint32_t codebase = orig_vbase + orig_slot_base;
    if (image_size <= slot && codebase >= kModCodeBase)
        return orig_vbase;   /* fits its slot and already in section 1 */

    /* Relocate below the lowest section-1 code (romimage grows dll_code_start
       down). Anchor on the code realaddr (CE3 has vbase+slot_base==codebase);
       new_vbase keeps slot_base. */
    if (ce_major > 5 || lowest_code == 0xFFFFFFFFu) {
        LOG(GuestAdditions, "%s image 0x%X overflows victim slot 0x%X; relocation "
                  "N/A (ce_major=%u lowest_code=0x%08X) - in-place at 0x%08X\n",
            victim_name, image_size, slot, ce_major, lowest_code, orig_vbase);
        return orig_vbase;
    }
    const uint32_t new_code = (lowest_code - image_size) & ~(kDllSlotAlign - 1u);
    if (new_code < kModCodeBase || new_code >= lowest_code) {
        LOG(GuestAdditions, "%s image 0x%X does not fit section-1 below 0x%08X - "
                  "in-place at 0x%08X\n", victim_name, image_size, lowest_code, orig_vbase);
        return orig_vbase;
    }
    const uint32_t new_vbase = new_code - orig_slot_base;

    /* The kernel only loads ROM DLLs inside [DllLoadBase, dlllast); when the
       relocated vbase falls below DllLoadBase, grow the region down by lowering
       dllfirst's high half (DllLoadBase). Keep the low half - on a CE3 ROM it is
       0 (no RW split), so no per-process reservation is added. */
    const uint32_t romhdr_pa     = pt.VaToPa(toc.romhdr_va);
    const uint32_t dllfirst      = mem.ReadWord(romhdr_pa);
    const uint32_t dll_load_base = dllfirst & 0xFFFF0000u;
    if (new_vbase < dll_load_base) {
        const uint32_t new_dllfirst = (new_vbase & 0xFFFF0000u) | (dllfirst & 0xFFFFu);
        mem.WriteWord(romhdr_pa, new_dllfirst);
        LOG(GuestAdditions, "%s grew DLL region: DllLoadBase 0x%08X -> 0x%08X "
                  "(dllfirst 0x%08X -> 0x%08X)\n",
            victim_name, dll_load_base, new_vbase & 0xFFFF0000u, dllfirst, new_dllfirst);
    }

    LOG(GuestAdditions, "%s overflows victim slot 0x%X; relocated code 0x%08X -> "
              "0x%08X, vbase 0x%08X -> 0x%08X (below lowest section-1 code 0x%08X)\n",
        victim_name, slot, orig_vbase + orig_slot_base, new_code,
        orig_vbase, new_vbase, lowest_code);
    return new_vbase;
}

