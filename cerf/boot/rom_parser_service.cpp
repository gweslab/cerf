#define NOMINMAX

#include "rom_parser_service.h"

#include "ce1_rom_parse.h"
#include "ce_imgfs_walker.h"
#include "rom_image_parse.h"
#include "rom_symbol_flash_parse.h"

#include "../boards/board_context.h"
#include "../core/cerf_emulator.h"
#include "../core/device_config.h"
#include "../core/log.h"
#include "../core/no_emulation_runtime_service.h"
#include "../core/cerf_paths.h"
#include "../core/string_utils.h"

#include <windows.h>

#include <cstring>
#include <fstream>

REGISTER_SERVICE(RomParserService);

namespace {

using cerf::ce1_rom_parse::ResolveCe1Xips;
using cerf::rom_image_parse::ArnoldLocateOsXip;
using cerf::rom_image_parse::ArnoldOsXip;
using cerf::rom_image_parse::AssembleB000FFFlat;
using cerf::rom_image_parse::FindAllEcec;
using cerf::rom_image_parse::FindImgfsBase;
using cerf::rom_image_parse::IpaqNbfLocateOsXip;
using cerf::rom_image_parse::IpaqNbfOsXip;
using cerf::rom_image_parse::ParseModulesAndFiles;
using cerf::rom_image_parse::NosajLocateOsXip;
using cerf::rom_image_parse::NosajOsXip;
using cerf::rom_image_parse::ResolveNextStructuralXip;
using cerf::rom_image_parse::ResolveRomhdrAtEcec;
using cerf::rom_image_parse::ResolveRomhdrStructural;
using cerf::rom_image_parse::SymbolFlashLocateOsXip;
using cerf::rom_image_parse::SymbolFlashOsXip;
using cerf::rom_image_parse::U32;
using cerf::rom_image_parse::kArnoldSignature;
using cerf::rom_image_parse::kB000FFSignature;
using cerf::rom_image_parse::kIpaqNbfSignature;
using cerf::rom_image_parse::kNosajSignature;

std::vector<uint8_t> ReadWholeFile(const std::string& path) {
    std::ifstream f(path, std::ios::binary | std::ios::ate);
    if (!f.is_open()) return {};
    const auto sz = f.tellg();
    std::vector<uint8_t> bytes(static_cast<size_t>(sz));
    f.seekg(0);
    f.read(reinterpret_cast<char*>(bytes.data()), sz);
    return bytes;
}

}  /* namespace */

bool RomParserService::ShouldRegister() {
    return emu_.Get<BoardContext>().GetRomPlacingMode()
        == RomPlacingMode::FlatContainer;
}

bool RomParserService::ParseCe1Xips(ParsedRom& rom) {
    uint32_t base_va = 0;
    if (!ResolveCe1Xips(rom.flat, rom.xips, base_va)) return false;

    rom.is_ce1       = true;
    rom.flat_base_va = base_va;
    for (size_t i = 0; i < rom.xips.size(); ++i) {
        const auto& h = rom.xips[i].toc.romhdr;
        LOG(Boot, "RomParser %s: CE1 xip[%zu] romhdr @ file off 0x%zX  "
                  "base_va=0x%08X  romhdr_va=0x%08X  "
                  "physfirst=0x%08X..physlast=0x%08X  nummods=%u  numfiles=%u\n",
            rom.filename.c_str(), i, size_t(rom.xips[i].toc.romhdr_va - base_va),
            base_va, rom.xips[i].toc.romhdr_va, h.physfirst, h.physlast,
            h.nummods, h.numfiles);
    }
    return true;
}

bool RomParserService::ParseOne(ParsedRom& rom) {
    rom.raw = ReadWholeFile(rom.path);
    if (rom.raw.empty()) {
        LOG(Caution, "RomParser: failed to read %s\n", rom.path.c_str());
        return false;
    }
    LOG(Boot, "RomParser: %s - %zu bytes (%.1f MB)\n",
        rom.path.c_str(), rom.raw.size(),
        double(rom.raw.size()) / 1024.0 / 1024.0);

    rom.is_b000ff = rom.raw.size() >= 7
                 && std::memcmp(rom.raw.data(), kB000FFSignature, 7) == 0;

    if (rom.is_b000ff) {
        if (!AssembleB000FFFlat(rom.raw, rom.flat_storage,
                                rom.flat_base_va, rom.entry_va,
                                rom.b000ff_sections)) {
            LOG(Caution, "RomParser %s: B000FF parse failed\n",
                rom.filename.c_str());
            return false;
        }
        rom.flat = std::span<const uint8_t>(rom.flat_storage);
    } else if (rom.raw.size() >= sizeof(kNosajSignature) &&
               std::memcmp(rom.raw.data(), kNosajSignature,
                           sizeof(kNosajSignature)) == 0) {
        NosajOsXip os;
        if (!NosajLocateOsXip(rom.raw, os)) {
            LOG(Caution, "RomParser %s: NOSAJ container but OS XIP not "
                         "resolvable\n", rom.filename.c_str());
            return false;
        }
        rom.is_nosaj     = true;
        rom.flat         = std::span<const uint8_t>(rom.raw)
                               .subspan(os.data_off, os.flat_size);
        rom.flat_base_va = os.base_va;
        rom.entry_va     = os.entry_va;
        LOG(Boot, "RomParser %s: NOSAJ container - OS XIP @ file 0x%zX "
                  "base=0x%08X entry=0x%08X span=%.1f MB\n",
            rom.filename.c_str(), os.data_off, os.base_va, os.entry_va,
            double(os.flat_size) / 1024.0 / 1024.0);
    } else if (rom.raw.size() >= sizeof(kArnoldSignature) &&
               std::memcmp(rom.raw.data(), kArnoldSignature,
                           sizeof(kArnoldSignature)) == 0) {
        ArnoldOsXip os;
        if (!ArnoldLocateOsXip(rom.raw, os)) {
            LOG(Caution, "RomParser %s: ARNOLDBOOTBLOCK package but OS XIP not "
                         "resolvable\n", rom.filename.c_str());
            return false;
        }
        rom.is_arnold    = true;
        rom.flat         = std::span<const uint8_t>(rom.raw)
                               .subspan(os.data_off, os.flat_size);
        rom.flat_base_va = os.base_va;
        LOG(Boot, "RomParser %s: ARNOLDBOOTBLOCK package - OS XIP @ file 0x%zX "
                  "base=0x%08X span=%.1f MB\n",
            rom.filename.c_str(), os.data_off, os.base_va,
            double(os.flat_size) / 1024.0 / 1024.0);
    } else if (rom.raw.size() >= sizeof(kIpaqNbfSignature) &&
               std::memcmp(rom.raw.data(), kIpaqNbfSignature,
                           sizeof(kIpaqNbfSignature)) == 0) {
        IpaqNbfOsXip os;
        if (!IpaqNbfLocateOsXip(rom.raw, os)) {
            LOG(Caution, "RomParser %s: iPAQ .nbf banner but OS XIP not "
                         "resolvable\n", rom.filename.c_str());
            return false;
        }
        rom.is_nbf       = true;
        rom.flat         = std::span<const uint8_t>(rom.raw)
                               .subspan(os.data_off, os.flat_size);
        rom.flat_base_va = 0;
        LOG(Boot, "RomParser %s: iPAQ .nbf package - OS XIP @ file 0x%zX "
                  "span=%.1f MB\n",
            rom.filename.c_str(), os.data_off,
            double(os.flat_size) / 1024.0 / 1024.0);
    } else {
        SymbolFlashOsXip sym;
        if (SymbolFlashLocateOsXip(rom.raw, sym)) {
            rom.is_symbol_flash = true;
            rom.flat            = std::span<const uint8_t>(rom.raw)
                                      .subspan(sym.data_off, sym.flat_size);
            rom.flat_base_va    = sym.base_va;
            rom.whole_flash_va  = sym.flash_va;
            LOG(Boot, "RomParser %s: Symbol whole-flash dump - part table @ "
                      "file 0x%zX, OS XIP @ file 0x%zX (%u blocks) base=0x%08X "
                      "flash kva=0x%08X span=%.1f MB\n",
                rom.filename.c_str(), sym.table_off, sym.data_off,
                sym.part_blocks, sym.base_va, sym.flash_va,
                double(sym.flat_size) / 1024.0 / 1024.0);
        } else {
            rom.flat = std::span<const uint8_t>(rom.raw);
            rom.flat_base_va = 0;
            LOG(Boot, "RomParser %s: NB0 flat %zu KB\n",
                rom.filename.c_str(), rom.flat.size() / 1024);
        }
    }

    const auto ececs = FindAllEcec(rom.flat);
    if (ececs.empty() && !ParseCe1Xips(rom)) {
        ParsedXipRegion xip;
        size_t          romhdr_off = 0;
        if (!ResolveRomhdrStructural(rom.flat, xip, romhdr_off)) {
            LOG(Caution, "RomParser %s: no ECEC marker and no structural "
                         "ROMHDR found\n", rom.filename.c_str());
            return false;
        }
        ParseModulesAndFiles(rom.flat, romhdr_off, xip.load_offset,
                             xip.toc.romhdr, xip.toc);
        const auto& h = xip.toc.romhdr;
        LOG(Boot, "RomParser %s: no ECEC marker - structural ROMHDR @ file "
                  "off 0x%zX  load_offset=0x%08X  romhdr_va=0x%08X  "
                  "physfirst=0x%08X..physlast=0x%08X  nummods=%u  numfiles=%u\n",
            rom.filename.c_str(), romhdr_off, xip.load_offset,
            xip.toc.romhdr_va, h.physfirst, h.physlast, h.nummods, h.numfiles);
        const uint32_t base_va = xip.load_offset;
        rom.xips.push_back(std::move(xip));

        for (size_t next = romhdr_off + 4;;) {
            ParsedXipRegion extra;
            size_t          extra_off = 0;
            if (!ResolveNextStructuralXip(rom.flat, next, base_va,
                                          extra, extra_off)) {
                break;
            }
            ParseModulesAndFiles(rom.flat, extra_off, extra.load_offset,
                                 extra.toc.romhdr, extra.toc);
            const auto& eh = extra.toc.romhdr;
            LOG(Boot, "RomParser %s: structural XIP[%zu] @ file off 0x%zX  "
                      "load_offset=0x%08X  romhdr_va=0x%08X  "
                      "physfirst=0x%08X..physlast=0x%08X  nummods=%u  "
                      "numfiles=%u\n",
                rom.filename.c_str(), rom.xips.size(), extra_off,
                extra.load_offset, extra.toc.romhdr_va, eh.physfirst,
                eh.physlast, eh.nummods, eh.numfiles);
            rom.xips.push_back(std::move(extra));
            next = extra_off + 4;
        }
    } else if (!ececs.empty()) {
        LOG(Boot, "RomParser %s: %zu ECEC marker(s) in flat\n",
            rom.filename.c_str(), ececs.size());

        for (size_t e : ececs) {
            ParsedXipRegion xip;
            size_t          romhdr_off = 0;
            if (!ResolveRomhdrAtEcec(rom.flat, e, rom.flat_base_va,
                                     xip, romhdr_off)) {
                LOG(Boot, "RomParser %s: ECEC @ 0x%zX did not resolve to a "
                          "valid ROMHDR; skipping this XIP region\n",
                    rom.filename.c_str(), e);
                continue;
            }
            ParseModulesAndFiles(rom.flat, romhdr_off, xip.load_offset,
                                 xip.toc.romhdr, xip.toc);
            const auto& h = xip.toc.romhdr;
            LOG(Boot, "RomParser %s: XIP[%zu] ECEC @ 0x%zX  load_offset=0x%08X  "
                      "romhdr_va=0x%08X  physfirst=0x%08X..physlast=0x%08X  "
                      "nummods=%u  numfiles=%u\n",
                rom.filename.c_str(), rom.xips.size(), e, xip.load_offset,
                xip.toc.romhdr_va, h.physfirst, h.physlast,
                h.nummods, h.numfiles);
            rom.xips.push_back(std::move(xip));
        }

        if (rom.xips.empty()) {
            LOG(Caution, "RomParser %s: no candidate ROMHDR validated "
                         "across %zu ECEC marker(s)\n",
                rom.filename.c_str(), ececs.size());
            return false;
        }
    }

    const auto& primary = rom.xips[0];
    if (rom.is_b000ff) {
        if (primary.load_offset != rom.flat_base_va) {
            LOG(Boot, "RomParser %s: B000FF section base 0x%08X (PA-form); "
                      "ECEC kernel-VA base 0x%08X; using kernel-VA for lookups\n",
                rom.filename.c_str(), rom.flat_base_va, primary.load_offset);
            rom.entry_va    += primary.load_offset - rom.flat_base_va;
            rom.flat_base_va = primary.load_offset;
        }
    } else if (!rom.is_nosaj) {
        rom.flat_base_va = primary.load_offset;
        rom.entry_va     = primary.toc.romhdr.physfirst;
        /* Kernel entry is the e32 entry point. physfirst can be a zero
           RomSignature pad the OS reuses for its sleep save block (SIMpad:
           e32_entryrva=0x1000), so a reset entering at physfirst after a suspend
           executes the save block. e32_entryrva=0 keeps entry_va == physfirst. */
        for (const auto& m : primary.toc.modules) {
            if (rom.is_ce1) break;
            if (m.ulLoadOffset != rom.entry_va) continue;   /* kernel = module @ physfirst */
            const size_t e32_off = size_t(m.ulE32Offset - rom.flat_base_va);
            if (e32_off + 12 > rom.flat.size()) break;
            const uint32_t entryrva = U32(rom.flat.data(), e32_off + 4);
            const uint32_t vbase    = U32(rom.flat.data(), e32_off + 8);
            if (vbase == rom.entry_va && entryrva < 0x01000000u)
                rom.entry_va = vbase + entryrva;
            break;
        }
    }

    if (!rom.is_b000ff && !rom.is_nosaj && !rom.is_arnold && !rom.is_nbf
        && !rom.is_ce1) {
        const size_t off = FindImgfsBase(rom.raw);
        if (off != SIZE_MAX) {
            rom.has_imgfs        = true;
            rom.imgfs_file_off   = uint32_t(off);
            const uint32_t bpb = U32(rom.raw.data(), off + 0x24);
            rom.imgfs_bytes_per_block = bpb;
            LOG(Boot, "RomParser %s: IMGFS superblock @ file offset 0x%zX "
                      "(%.1f MB into image), bytes_per_block=0x%X\n",
                rom.filename.c_str(), off,
                double(off) / 1024.0 / 1024.0, bpb);

            auto tr = cerf::ce_imgfs_walker::Translator::Detect(rom.raw, off);
            rom.imgfs_is_ftl = tr.IsFtl();
            auto mods = cerf::ce_imgfs_walker::CollectModules(
                rom.raw, tr, bpb);
            rom.imgfs_modules.reserve(mods.size());
            for (auto& m : mods) {
                ParsedImgfsModule out;
                out.lpszFileName    = std::move(m.name);
                out.dirent_file_off = m.dirent_off;
                out.file_size       = m.file_size;
                out.mod_indexptr    = m.mod_indexptr;
                out.mod_indexsize   = m.mod_indexsize;
                out.sections.reserve(m.sections.size());
                for (auto& s : m.sections) {
                    ParsedImgfsModule::Section ps;
                    ps.name            = std::move(s.name);
                    ps.dirent_file_off = s.dirent_off;
                    ps.file_size       = s.file_size;
                    ps.sec_indexptr    = s.sec_indexptr;
                    ps.sec_indexsize   = s.sec_indexsize;
                    out.sections.push_back(std::move(ps));
                }
                rom.imgfs_modules.push_back(std::move(out));
            }
            LOG(Boot, "RomParser %s: IMGFS %s, %zu module(s)\n",
                rom.filename.c_str(),
                rom.imgfs_is_ftl ? "FTL-mapped" : "direct-addressed",
                rom.imgfs_modules.size());
            /* Diagnostic: log section index pointers for victim + gwes -
               lets the injector cross-compare which IMGFS pages it's
               writing to and whether they overlap any other module's
               storage (the WM6.5 gwes UND crash signature). */
            for (const auto& m : rom.imgfs_modules) {
                const bool relevant =
                    _stricmp(m.lpszFileName.c_str(), "gwes.exe") == 0
                 || _stricmp(m.lpszFileName.c_str(), "DeviceEmulator_lcd.dll") == 0
                 || _stricmp(m.lpszFileName.c_str(), "ddi.dll") == 0;
                if (!relevant) continue;
                LOG(Boot, "RomParser %s: IMGFS module %s dirent=0x%zX "
                          "mod_idx=0x%X(size=%u)\n",
                    rom.filename.c_str(), m.lpszFileName.c_str(),
                    m.dirent_file_off, m.mod_indexptr, m.mod_indexsize);
                for (size_t si = 0; si < m.sections.size(); ++si) {
                    const auto& s = m.sections[si];
                    LOG(Boot, "RomParser %s:   %s sec[%zu] dirent=0x%zX "
                              "sec_idx=0x%X(size=%u)\n",
                        rom.filename.c_str(), m.lpszFileName.c_str(), si,
                        s.dirent_file_off, s.sec_indexptr, s.sec_indexsize);
                }
            }
        }
    }

    /* Per-module / per-file logging - flatten across every XIP. */
    for (size_t xi = 0; xi < rom.xips.size(); ++xi) {
        const auto& xip = rom.xips[xi];
        for (size_t i = 0; i < xip.toc.modules.size(); ++i) {
            const auto& m = xip.toc.modules[i];
            LOG(Boot, "RomParser %s:   xip[%zu] mod[%zu] %-32s loadVA=0x%08X "
                      "size=%u e32=0x%08X o32=0x%08X attrs=0x%X\n",
                rom.filename.c_str(), xi, i, m.lpszFileName.c_str(),
                m.ulLoadOffset, m.nFileSize, m.ulE32Offset, m.ulO32Offset,
                m.dwFileAttributes);
        }
        for (size_t i = 0; i < xip.toc.files.size(); ++i) {
            const auto& f = xip.toc.files[i];
            LOG(Boot, "RomParser %s:   xip[%zu] file[%zu] %-32s "
                      "loadVA=0x%08X rsz=%u csz=%u attrs=0x%X\n",
                rom.filename.c_str(), xi, i, f.lpszFileName.c_str(),
                f.ulLoadOffset, f.nRealFileSize, f.nCompFileSize,
                f.dwFileAttributes);
        }
    }
    LOG(Boot, "RomParser %s: %zu XIP region(s), entry kva=0x%08X\n",
        rom.filename.c_str(), rom.xips.size(), rom.entry_va);
    return true;
}

void RomParserService::OnReady() {
    emu_.Get<NoEmulationRuntimeService>().EnsureEmulationPrevented();

    const auto& cfg = emu_.Get<DeviceConfig>();

    std::vector<std::string> filenames;
    if (cfg.boot_in_recovery) {
        if (cfg.rom_recovery.empty()) {
            LOG(Caution, "RomParser: --recovery requested but device '%s' "
                         "declares no rom.recovery\n", cfg.device_name.c_str());
            return;
        }
        LOG(Boot, "RomParser: RECOVERY MODE - booting %s\n",
            cfg.rom_recovery.c_str());
        filenames.push_back(cfg.rom_recovery);
    } else {
        if (cfg.rom_primary.empty()) {
            LOG(Caution, "RomParser: device '%s' declares no rom.primary "
                         "(set rom.primary in cerf.json or pass "
                         "--rom-primary=FILE)\n", cfg.device_name.c_str());
            return;
        }
        filenames.push_back(cfg.rom_primary);
        for (const auto& ext : cfg.rom_extensions) filenames.push_back(ext);
        if (!cfg.rom_recovery.empty()) {
            LOG(Boot, "RomParser: rom_recovery=%s declared, not loaded "
                      "(pass --recovery to boot it)\n",
                cfg.rom_recovery.c_str());
        }
    }

    loaded_.reserve(filenames.size());
    for (size_t i = 0; i < filenames.size(); ++i) {
        ParsedRom rom;
        rom.filename = filenames[i];
        rom.path     = ResolveDeviceFile(cfg.device_name, filenames[i]);
        if (!ParseOne(rom)) {
            loaded_.clear();
            return;
        }
        loaded_.push_back(std::move(rom));
    }

    LOG(Boot, "RomParser: %zu partition(s) loaded (primary=%s%s)\n",
        loaded_.size(), loaded_[0].filename.c_str(),
        loaded_.size() > 1 ? ", +extensions" : "");

    uint16_t ce_major = 0, ce_minor = 0;
    if (KernelSubsystemVersion(ce_major, ce_minor))
        LOG(Boot, "RomParser: kernel subsystem version %u.%u\n",
            ce_major, ce_minor);

    ok_ = true;
}
