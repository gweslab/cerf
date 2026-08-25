#define NOMINMAX

#include "rom_placer.h"

#include "board_boot_placer.h"
#include "guest_cold_boot.h"
#include "rom_parser_service.h"

#include "../boards/board_context.h"
#include "../core/cerf_emulator.h"
#include "../core/log.h"
#include "../cpu/emulated_memory.h"
#include "../boards/page_table_builder.h"

#include <algorithm>
#include <cstdint>
#include <cstring>

REGISTER_SERVICE(RomPlacer);

bool RomPlacer::ShouldRegister() {
    return emu_.Get<BoardContext>().GetRomPlacingMode()
        == RomPlacingMode::FlatContainer;
}

bool RomPlacer::IsVolatilePa(uint32_t pa) {
    for (const auto& r : emu_.Get<PageTableBuilder>().BackedMemoryRegions()) {
        if (pa < r.pa_base || pa >= r.pa_base + r.size) continue;
        return r.page_protect != PAGE_READONLY &&
               r.page_protect != PAGE_EXECUTE_READ;
    }
    return true;
}

void RomPlacer::PlaceRomXips(const ParsedRom& rom, bool volatile_only) {
    auto& page_tables = emu_.Get<PageTableBuilder>();
    auto& mem         = emu_.Get<EmulatedMemory>();

    for (size_t i = 0; i < rom.xips.size(); ++i) {
        const auto& xip = rom.xips[i];
        const uint32_t physfirst = xip.toc.romhdr.physfirst;
        const uint32_t physlast  = xip.toc.romhdr.physlast;
        if (physlast <= physfirst) continue;

        if (physfirst < xip.load_offset) {
            LOG(Caution,
                "RomPlacer %s: xip[%zu] physfirst=0x%08X below "
                "load_offset=0x%08X - skipping\n",
                rom.filename.c_str(), i, physfirst, xip.load_offset);
            continue;
        }

        const size_t file_off = size_t(physfirst - xip.load_offset);
        const size_t xip_len  = size_t(physlast - physfirst);
        if (file_off >= rom.flat.size()) {
            LOG(Caution,
                "RomPlacer %s: xip[%zu] file_off=0x%zX past flat "
                "size=%zu - skipping\n",
                rom.filename.c_str(), i, file_off, rom.flat.size());
            continue;
        }
        const size_t copy_len =
            std::min(xip_len, rom.flat.size() - file_off);

        /* One CopyIn per VA->PA-contiguous run, not one flat copy: a CE
           image crossing non-contiguous OAT bands (SIMpad's DRAM head +
           flash-XIP body) needs each run at its mapped PA; a single-band
           image yields one run identical to the old behavior. */
        const uint32_t img_end = physfirst + uint32_t(copy_len);
        uint32_t run_va = physfirst;
        while (run_va < img_end) {
            const uint32_t run_pa = page_tables.VaToPa(run_va);
            uint32_t va = run_va;
            do {
                va += 0x1000u;
            } while (va < img_end &&
                     page_tables.VaToPa(va) == run_pa + (va - run_va));
            const uint32_t run_end = std::min(va, img_end);
            const uint32_t run_len = run_end - run_va;
            if (volatile_only && !IsVolatilePa(run_pa)) {
                run_va = run_end;
                continue;
            }
            const size_t src_off = file_off + size_t(run_va - physfirst);
            mem.CopyIn(run_pa, rom.flat.data() + src_off, run_len);
            LOG(Boot,
                "RomPlacer %s: xip[%zu] run %u bytes  src_off=0x%zX  "
                "kva=0x%08X..0x%08X  pa=0x%08X\n",
                rom.filename.c_str(), i, run_len, src_off,
                run_va, run_end, run_pa);
            run_va = run_end;
        }
    }
}

void RomPlacer::PlaceB000FFSections(const ParsedRom& rom, bool volatile_only) {
    auto& page_tables = emu_.Get<PageTableBuilder>();
    auto& mem         = emu_.Get<EmulatedMemory>();
    const auto backed = page_tables.BackedMemoryRegions();

    /* Copy [va_lo, va_hi) of section `s` to its backed-region PA(s). A VA
       outside every backed band has no destination and is skipped; one
       straddling bands is split per band. */
    auto place = [&](uint32_t va_lo, uint32_t va_hi, const B000FFSection& s) {
        for (const auto& reg : backed) {
            const uint64_t lo = std::max<uint64_t>(va_lo, reg.va_base);
            const uint64_t hi = std::min<uint64_t>(va_hi,
                                    uint64_t(reg.va_base) + reg.size);
            if (lo >= hi) continue;
            const uint32_t pa = reg.pa_base + uint32_t(lo - reg.va_base);
            if (volatile_only && !IsVolatilePa(pa)) continue;
            const size_t   src_off = s.data_off + size_t(lo - s.base);
            const uint32_t len     = uint32_t(hi - lo);
            if (src_off + len > rom.raw.size()) continue;
            mem.CopyIn(pa, rom.raw.data() + src_off, len);
            LOG(Boot,
                "RomPlacer %s: b000ff tail kva=0x%08X..0x%08X  pa=0x%08X  "
                "%u bytes%s\n",
                rom.filename.c_str(), uint32_t(lo), uint32_t(hi), pa, len,
                volatile_only ? " (replay)" : "");
        }
    };

    /* PlaceRomXips already copied every XIP region's physfirst..physlast, so
       here we add ONLY the section bytes outside all of them - the multi-XIP
       XIPCHAIN table living past the kernel ROMHDR's physlast. A single-XIP
       image has no such bytes, so its placement is unchanged. */
    for (const auto& s : rom.b000ff_sections) {
        if (s.size == 0) continue;
        uint64_t       cur = s.base;
        const uint64_t end = uint64_t(s.base) + s.size;
        while (cur < end) {
            uint64_t cover_end  = cur;   /* end of an XIP range covering cur */
            uint64_t next_start = end;   /* start of the next XIP range > cur */
            for (const auto& xip : rom.xips) {
                const uint64_t xs = xip.toc.romhdr.physfirst;
                const uint64_t xe = xip.toc.romhdr.physlast;
                if (xe <= xs) continue;
                if (xs <= cur && cur < xe)      cover_end  = std::max(cover_end, xe);
                else if (cur < xs && xs < next_start) next_start = xs;
            }
            if (cover_end > cur) { cur = cover_end; continue; }
            const uint64_t place_to = std::min(end, next_start);
            place(uint32_t(cur), uint32_t(place_to), s);
            cur = place_to;
        }
    }
}

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
        PlaceRomXips(rom, /*volatile_only=*/false);

        if (rom.is_b000ff) {
            /* Add the section bytes past every XIP's physfirst..physlast (the
               multi-XIP XIPCHAIN table); single-XIP images place nothing here. */
            PlaceB000FFSections(rom, /*volatile_only=*/false);
            continue;
        }

        {
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
                const bool whole_flash =
                    rom.is_symbol_flash
                    && page_tables.VaToPa(rom.whole_flash_va) == flash_pa_base;
                const uint8_t* src =
                    whole_flash ? rom.raw.data() : rom.flat.data();
                const size_t   len =
                    whole_flash ? rom.raw.size() : rom.flat.size();
                const size_t file_len = std::min<size_t>(len, flash_size);
                mem.CopyIn(flash_pa_base, src, file_len);
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
                    "to a Flash backed region - IMGFS bytes will not be "
                    "reachable, userspace mount will fail\n",
                    rom.filename.c_str());
            }
        }
    }

    if (auto* bp = emu_.TryGet<BoardBootPlacer>()) bp->PlaceAfterRom();

    emu_.Get<GuestColdBoot>().RegisterReplay([this] {
        for (const auto& rom : emu_.Get<RomParserService>().Loaded()) {
            PlaceRomXips(rom, /*volatile_only=*/true);
            if (rom.is_b000ff)
                PlaceB000FFSections(rom, /*volatile_only=*/true);
        }
    });
}
