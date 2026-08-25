#define NOMINMAX

#include "../board_context.h"
#include "../page_table_builder.h"

#include "../../boot/board_boot_placer.h"
#include "../../boot/rom_image_parse.h"
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
#include <fstream>
#include <string>
#include <vector>

namespace {

/* symbol_mk500 dump.bin 0x00180040 ECEC == MK500c50BenOS013014.bin ImageStart 0x80180000 + 0x40: dump offset == flash PA. */
/* symbol_mk500 dump.bin 0x00080040 partition table: Monitor blk 0 -> 0x0, Windows CE blk 6 -> 0x180000, Platform blk 0x80 -> 0x2000000, Application blk 0xA0 -> 0x2800000; erase block 0x40000. */
/* symbol_mk500 MK500c50BenPL014.bin / MK500c50BenAP014.bin B000FF ImageStart 0xA2000000 / 0xA2800000 == those partition PAs + 0xA0000000. */

constexpr size_t   kChunkBytes   = 4u * 1024 * 1024;
constexpr uint32_t kVolumePaMask = 0x1FFFFFFFu;

bool FileExists(const std::string& path) {
    const DWORD a = ::GetFileAttributesW(Utf8ToWide(path.c_str()).c_str());
    return a != INVALID_FILE_ATTRIBUTES && !(a & FILE_ATTRIBUTE_DIRECTORY);
}

std::vector<uint8_t> ReadWholeFile(const std::string& path) {
    std::ifstream f(path, std::ios::binary | std::ios::ate);
    if (!f.is_open()) return {};
    const auto sz = f.tellg();
    std::vector<uint8_t> bytes(static_cast<size_t>(sz));
    f.seekg(0);
    f.read(reinterpret_cast<char*>(bytes.data()), sz);
    return bytes;
}

class SymbolMk500FlashPlacer : public BoardBootPlacer {
public:
    using BoardBootPlacer::BoardBootPlacer;

    bool ShouldRegister() override {
        auto* bd = emu_.TryGet<BoardContext>();
        if (!bd || bd->GetBoard() != Board::SymbolMk500) return false;
        const auto& cfg = emu_.Get<DeviceConfig>();
        if (!cfg.rom_flash.empty()
            && FileExists(ResolveDeviceFile(cfg.device_name, cfg.rom_flash)))
            return true;
        for (const auto& v : cfg.rom_volumes) {
            if (FileExists(ResolveDeviceFile(cfg.device_name, v))) return true;
        }
        for (const auto& r : cfg.rom_flash_regions) {
            if (FileExists(ResolveDeviceFile(cfg.device_name, r.file))) return true;
        }
        return false;
    }

    void PlaceAfterRom() override;

private:
    uint64_t CopySpan(uint32_t pa_lo, uint32_t pa_hi);
    void     PlaceWholeDump();
    void     PlaceVolume(const std::string& file);
    void     PlaceRawRegion(const RomFlashRegion& region);
    bool     FlashBacked(uint32_t pa, uint32_t size) const;

    MappedFile mf_;
};

bool SymbolMk500FlashPlacer::FlashBacked(uint32_t pa, uint32_t size) const {
    for (const auto& r : emu_.Get<PageTableBuilder>().BackedMemoryRegions()) {
        if (r.page_protect != PAGE_READONLY) continue;
        if (pa < r.pa_base) continue;
        if (uint64_t(pa) + size > uint64_t(r.pa_base) + r.size) continue;
        return true;
    }
    return false;
}

uint64_t SymbolMk500FlashPlacer::CopySpan(uint32_t pa_lo, uint32_t pa_hi) {
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

void SymbolMk500FlashPlacer::PlaceWholeDump() {
    const auto&       cfg  = emu_.Get<DeviceConfig>();
    const std::string path = ResolveDeviceFile(cfg.device_name, cfg.rom_flash);

    if (!mf_.Open(path)) {
        LOG(Caution, "SymbolMk500FlashPlacer: failed to map %s\n", path.c_str());
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

        LOG(Boot, "SymbolMk500FlashPlacer: %s -> flash pa=0x%08X..0x%08X, "
                  "%.1f MB placed, OS image span pa=0x%08X..0x%08X kept\n",
            cfg.rom_flash.c_str(), lo, hi,
            double(placed) / 1024.0 / 1024.0, skip_lo, skip_hi);
    }
}

void SymbolMk500FlashPlacer::PlaceVolume(const std::string& file) {
    const auto&       cfg  = emu_.Get<DeviceConfig>();
    const std::string path = ResolveDeviceFile(cfg.device_name, file);

    const std::vector<uint8_t> raw = ReadWholeFile(path);
    if (raw.empty()) {
        LOG(Caution, "SymbolMk500FlashPlacer: failed to read volume %s\n",
            path.c_str());
        return;
    }

    std::vector<B000FFSection> sections;
    uint32_t image_start  = 0;
    uint32_t image_length = 0;
    uint32_t terminator   = 0;
    if (!cerf::rom_image_parse::B000FFSectionTable(
            raw, sections, image_start, image_length, terminator)) {
        LOG(Caution, "SymbolMk500FlashPlacer: %s is not a B000FF volume "
                     "image - not placed\n", file.c_str());
        return;
    }

    auto&    mem     = emu_.Get<EmulatedMemory>();
    uint64_t placed  = 0;
    uint32_t skipped = 0;
    uint32_t pa_lo   = 0xFFFFFFFFu;
    uint32_t pa_hi   = 0;
    for (const auto& s : sections) {
        const uint32_t pa = s.base & kVolumePaMask;
        if (!FlashBacked(pa, s.size)) { ++skipped; continue; }
        mem.CopyIn(pa, raw.data() + s.data_off, s.size);
        placed += s.size;
        pa_lo   = std::min(pa_lo, pa);
        pa_hi   = std::max(pa_hi, pa + s.size);
    }

    LOG(Boot, "SymbolMk500FlashPlacer: %s volume start=0x%08X len=0x%08X "
              "end=0x%08X, %zu section(s) -> flash pa=0x%08X..0x%08X, "
              "%.2f MB placed, %u section(s) outside flash\n",
        file.c_str(), image_start, image_length, terminator, sections.size(),
        placed ? pa_lo : 0u, pa_hi, double(placed) / 1024.0 / 1024.0, skipped);
}

void SymbolMk500FlashPlacer::PlaceRawRegion(const RomFlashRegion& region) {
    const auto&       cfg  = emu_.Get<DeviceConfig>();
    const std::string path = ResolveDeviceFile(cfg.device_name, region.file);

    const std::vector<uint8_t> raw = ReadWholeFile(path);
    if (raw.empty()) {
        LOG(Caution, "SymbolMk500FlashPlacer: failed to read flash region %s\n",
            path.c_str());
        return;
    }
    if (!FlashBacked(region.pa, uint32_t(raw.size()))) {
        LOG(Caution, "SymbolMk500FlashPlacer: %s pa=0x%08X size=0x%zX is "
                     "outside flash - not placed\n",
            region.file.c_str(), region.pa, raw.size());
        return;
    }

    emu_.Get<EmulatedMemory>().CopyIn(region.pa, raw.data(), raw.size());
    LOG(Boot, "SymbolMk500FlashPlacer: %s -> flash pa=0x%08X..0x%08X "
              "(%zu bytes) placed\n",
        region.file.c_str(), region.pa,
        region.pa + uint32_t(raw.size()), raw.size());
}

void SymbolMk500FlashPlacer::PlaceAfterRom() {
    const auto& cfg = emu_.Get<DeviceConfig>();

    if (!cfg.rom_flash.empty()
        && FileExists(ResolveDeviceFile(cfg.device_name, cfg.rom_flash)))
        PlaceWholeDump();

    for (const auto& r : cfg.rom_flash_regions) PlaceRawRegion(r);
    for (const auto& v : cfg.rom_volumes)       PlaceVolume(v);
}

}  /* namespace */

REGISTER_SERVICE_AS(SymbolMk500FlashPlacer, BoardBootPlacer);
