#define NOMINMAX

#include "rom_placer.h"

#include "rom_parser_service.h"

#include "../core/cerf_emulator.h"
#include "../core/log.h"
#include "../cpu/emulated_memory.h"
#include "../boards/page_table_builder.h"

#include <algorithm>
#include <cstdint>
#include <cstring>

REGISTER_SERVICE(RomPlacer);

namespace {

struct CopyClip {
    uint32_t pa_start;
    uint32_t file_off;
    size_t   length;
};

}  /* namespace */

void RomPlacer::OnReady() {
    auto& parser = emu_.Get<RomParserService>();
    if (!parser.Ok()) {
        LOG(Caution, "RomPlacer: parser not ready, nothing to place\n");
        return;
    }
    auto& page_tables = emu_.Get<PageTableBuilder>();
    if (page_tables.BackedMemoryRegions().empty()) {
        LOG(Boot, "RomPlacer: no backed regions; nothing to place\n");
        return;
    }
    auto& mem         = emu_.Get<EmulatedMemory>();

    for (const auto& r : page_tables.BackedMemoryRegions()) {
        if (r.page_protect == PAGE_READONLY) {
            std::memset(mem.Translate(r.pa_base), 0xFF, r.size);
            LOG(Boot, "RomPlacer: flash region pa=0x%08X size=0x%X "
                      "initialised to 0xFF (NOR erased state)\n",
                r.pa_base, r.size);
        }
    }

    for (const auto& rom : parser.Loaded()) {
        for (size_t i = 0; i < rom.xips.size(); ++i) {
            const auto& xip = rom.xips[i];
            const uint32_t physfirst = xip.toc.romhdr.physfirst;
            const uint32_t physlast  = xip.toc.romhdr.physlast;
            if (physlast <= physfirst) continue;

            if (physfirst < xip.load_offset) {
                LOG(Caution,
                    "RomPlacer %s: xip[%zu] physfirst=0x%08X below "
                    "load_offset=0x%08X — skipping\n",
                    rom.filename.c_str(), i, physfirst, xip.load_offset);
                continue;
            }

            const size_t file_off = size_t(physfirst - xip.load_offset);
            const size_t xip_len  = size_t(physlast - physfirst);
            if (file_off >= rom.flat.size()) {
                LOG(Caution,
                    "RomPlacer %s: xip[%zu] file_off=0x%zX past flat "
                    "size=%zu — skipping\n",
                    rom.filename.c_str(), i, file_off, rom.flat.size());
                continue;
            }
            const size_t copy_len =
                std::min(xip_len, rom.flat.size() - file_off);
            const uint32_t pa_base = page_tables.VaToPa(physfirst);

            mem.CopyIn(pa_base, rom.flat.data() + file_off, copy_len);
            LOG(Boot,
                "RomPlacer %s: xip[%zu] %zu bytes  file_off=0x%zX  "
                "kva=0x%08X..0x%08X  pa=0x%08X\n",
                rom.filename.c_str(), i, copy_len, file_off,
                physfirst, uint32_t(physfirst + copy_len), pa_base);
        }

        if (!rom.is_b000ff) {
            uint32_t flash_va_base = 0;
            uint32_t flash_pa_base = 0;
            uint32_t flash_size    = 0;
            bool     have_flash    = false;
            for (const auto& xip : rom.xips) {
                const uint32_t va = xip.load_offset;
                const uint32_t pa = page_tables.VaToPa(va);
                for (const auto& reg : page_tables.BackedMemoryRegions()) {
                    if (reg.page_protect != PAGE_READONLY) continue;
                    if (pa < reg.pa_base) continue;
                    if (pa >= reg.pa_base + reg.size) continue;
                    flash_va_base = va;
                    flash_pa_base = reg.pa_base;
                    flash_size    = reg.size;
                    have_flash    = true;
                    break;
                }
                if (have_flash) break;
            }
            if (have_flash) {
                const uint32_t bank_va_base =
                    flash_va_base - (page_tables.VaToPa(flash_va_base)
                                     - flash_pa_base);
                const size_t file_len =
                    std::min<size_t>(rom.flat.size(), flash_size);
                mem.CopyIn(flash_pa_base, rom.flat.data(), file_len);
                LOG(Boot,
                    "RomPlacer %s: full flash image %zu bytes placed at "
                    "kva=0x%08X..0x%08X  pa=0x%08X..0x%08X  "
                    "(fills inter-XIP gaps incl. XIPCHAIN table)\n",
                    rom.filename.c_str(), file_len,
                    bank_va_base, uint32_t(bank_va_base + file_len),
                    flash_pa_base, uint32_t(flash_pa_base + file_len));
            } else if (rom.has_imgfs) {
                LOG(Caution,
                    "RomPlacer %s: IMGFS present but no XIP region maps "
                    "to a Flash backed region — IMGFS bytes will not be "
                    "reachable, userspace mount will fail\n",
                    rom.filename.c_str());
            }
        }
    }
}
