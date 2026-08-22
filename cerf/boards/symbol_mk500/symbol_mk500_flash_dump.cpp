#define NOMINMAX

#include "../board_context.h"
#include "../page_table_builder.h"

#include "../../boot/board_boot_placer.h"
#include "../../boot/rom_parser_service.h"
#include "../../core/cerf_emulator.h"
#include "../../core/cerf_paths.h"
#include "../../core/device_config.h"
#include "../../core/log.h"
#include "../../core/string_utils.h"
#include "../../cpu/emulated_memory.h"
#include "../../storage/mapped_file.h"

#include <windows.h>

#include <algorithm>
#include <cstdint>
#include <string>

namespace {

/* dump.bin ROM offset 0x00180040 ECEC == MK500c50BenOS013014.bin ImageStart 0x80180000 + 0x40: dump offset == flash PA. */
/* dump.bin ROM offset 0x00080000 partition table: [27] Monitor 0, [22] Config Block 0x82000, [25] Windows CE 0x180000. */

constexpr size_t kChunkBytes = 4u * 1024 * 1024;

bool FileExists(const std::string& path) {
    const DWORD a = ::GetFileAttributesW(Utf8ToWide(path.c_str()).c_str());
    return a != INVALID_FILE_ATTRIBUTES && !(a & FILE_ATTRIBUTE_DIRECTORY);
}

class SymbolMk500FlashDump : public BoardBootPlacer {
public:
    using BoardBootPlacer::BoardBootPlacer;

    bool ShouldRegister() override {
        auto* bd = emu_.TryGet<BoardContext>();
        if (!bd || bd->GetBoard() != Board::SymbolMk500) return false;
        const auto& cfg = emu_.Get<DeviceConfig>();
        if (cfg.rom_flash.empty()) return false;
        return FileExists(ResolveDeviceFile(cfg.device_name, cfg.rom_flash));
    }

    void PlaceAfterRom() override;

private:
    uint64_t CopySpan(uint32_t pa_lo, uint32_t pa_hi);

    MappedFile mf_;
};

uint64_t SymbolMk500FlashDump::CopySpan(uint32_t pa_lo, uint32_t pa_hi) {
    auto& mem = emu_.Get<EmulatedMemory>();

    uint64_t done = 0;
    for (uint32_t pa = pa_lo; pa < pa_hi;) {
        const size_t want =
            size_t(std::min<uint64_t>(kChunkBytes, pa_hi - pa));
        const uint8_t* src = mf_.View(pa, want);
        if (!src) break;
        mem.CopyIn(pa, src, want);
        pa   += uint32_t(want);
        done += want;
    }
    return done;
}

void SymbolMk500FlashDump::PlaceAfterRom() {
    const auto&       cfg  = emu_.Get<DeviceConfig>();
    const std::string path = ResolveDeviceFile(cfg.device_name, cfg.rom_flash);

    if (!mf_.Open(path)) {
        LOG(Caution, "SymbolMk500FlashDump: failed to map %s\n", path.c_str());
        return;
    }

    uint32_t skip_lo = 0;
    uint32_t skip_hi = 0;
    auto&    parser  = emu_.Get<RomParserService>();
    if (parser.Ok() && !parser.Loaded().empty()) {
        const ParsedRom& rom = parser.Primary();
        skip_lo = emu_.Get<PageTableBuilder>().VaToPa(rom.flat_base_va);
        skip_hi = skip_lo + uint32_t(rom.flat.size());
    }

    for (const auto& r : emu_.Get<PageTableBuilder>().BackedMemoryRegions()) {
        if (r.page_protect != PAGE_READONLY) continue;

        const uint32_t lo = r.pa_base;
        const uint32_t hi = uint32_t(std::min<uint64_t>(
            uint64_t(r.pa_base) + r.size, mf_.Size()));
        if (hi <= lo) continue;

        uint64_t placed = 0;
        if (skip_hi > skip_lo && skip_lo < hi && lo < skip_hi) {
            if (lo < skip_lo)  placed += CopySpan(lo, skip_lo);
            if (skip_hi < hi)  placed += CopySpan(skip_hi, hi);
        } else {
            placed = CopySpan(lo, hi);
        }

        LOG(Boot, "SymbolMk500FlashDump: %s -> flash pa=0x%08X..0x%08X, "
                  "%.1f MB placed, OS image span pa=0x%08X..0x%08X kept\n",
            cfg.rom_flash.c_str(), lo, hi,
            double(placed) / 1024.0 / 1024.0, skip_lo, skip_hi);
    }
}

}  /* namespace */

REGISTER_SERVICE_AS(SymbolMk500FlashDump, BoardBootPlacer);
