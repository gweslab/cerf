#define NOMINMAX

#include "rom_parser_service.h"

#include "ce_imgfs_walker.h"
#include "rom_image_parse.h"

#include "../core/cerf_emulator.h"
#include "../core/device_config.h"
#include "../core/log.h"
#include "../core/string_utils.h"

#include <windows.h>

#include <cctype>
#include <cstring>
#include <fstream>

REGISTER_SERVICE(RomParserService);

namespace {

using cerf::rom_image_parse::AssembleB000FFFlat;
using cerf::rom_image_parse::FindAllEcec;
using cerf::rom_image_parse::FindImgfsBase;
using cerf::rom_image_parse::ParseModulesAndFiles;
using cerf::rom_image_parse::ResolveRomhdrAtEcec;
using cerf::rom_image_parse::ResolveRomhdrStructural;
using cerf::rom_image_parse::U32;
using cerf::rom_image_parse::kB000FFSignature;

inline char AsciiLower(char c) {
    return char(std::tolower(static_cast<unsigned char>(c)));
}

bool EqualIgnoreCase(const std::string& a, const char* b) {
    size_t blen = std::strlen(b);
    if (a.size() != blen) return false;
    for (size_t i = 0; i < blen; ++i) {
        if (AsciiLower(a[i]) != AsciiLower(b[i])) return false;
    }
    return true;
}

/* Scan a directory for the first *.nb0 / *.bin file (single-ROM
   auto-detect mode when cerf.json lists no partitions). */
std::string FindFirstRomFile(const std::string& device_dir) {
    const std::wstring pattern = Utf8ToWide((device_dir + "*").c_str());
    WIN32_FIND_DATAW fd{};
    HANDLE h = FindFirstFileW(pattern.c_str(), &fd);
    if (h == INVALID_HANDLE_VALUE) return {};
    std::string result;
    do {
        if (fd.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) continue;
        std::string name = WideToUtf8(fd.cFileName);
        if (name.size() < 5) continue;
        std::string ext = name.substr(name.size() - 4);
        for (auto& c : ext) c = AsciiLower(c);
        if (ext == ".nb0" || ext == ".bin") {
            result = name;
            break;
        }
    } while (FindNextFileW(h, &fd));
    FindClose(h);
    return result;
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

}  /* namespace */

bool RomParserService::ParseOne(ParsedRom& rom) {
    rom.raw = ReadWholeFile(rom.path);
    if (rom.raw.empty()) {
        LOG(Caution, "RomParser: failed to read %s\n", rom.path.c_str());
        return false;
    }
    LOG(Boot, "RomParser: %s — %zu bytes (%.1f MB)\n",
        rom.path.c_str(), rom.raw.size(),
        double(rom.raw.size()) / 1024.0 / 1024.0);

    rom.is_b000ff = rom.raw.size() >= 7
                 && std::memcmp(rom.raw.data(), kB000FFSignature, 7) == 0;

    if (rom.is_b000ff) {
        if (!AssembleB000FFFlat(rom.raw, rom.flat_storage,
                                rom.flat_base_va, rom.entry_va)) {
            LOG(Caution, "RomParser %s: B000FF parse failed\n",
                rom.filename.c_str());
            return false;
        }
        rom.flat = std::span<const uint8_t>(rom.flat_storage);
    } else {
        rom.flat = std::span<const uint8_t>(rom.raw);
        rom.flat_base_va = 0;
        LOG(Boot, "RomParser %s: NB0 flat %zu KB\n",
            rom.filename.c_str(), rom.flat.size() / 1024);
    }

    const auto ececs = FindAllEcec(rom.flat);
    if (ececs.empty()) {
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
        LOG(Boot, "RomParser %s: no ECEC marker — structural ROMHDR @ file "
                  "off 0x%zX  load_offset=0x%08X  romhdr_va=0x%08X  "
                  "physfirst=0x%08X..physlast=0x%08X  nummods=%u  numfiles=%u\n",
            rom.filename.c_str(), romhdr_off, xip.load_offset,
            xip.toc.romhdr_va, h.physfirst, h.physlast, h.nummods, h.numfiles);
        rom.xips.push_back(std::move(xip));
    } else {
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
    } else {
        rom.flat_base_va = primary.load_offset;
        rom.entry_va     = primary.toc.romhdr.physfirst;
    }

    if (!rom.is_b000ff) {
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
            /* Diagnostic: log section index pointers for victim + gwes —
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

    /* Per-module / per-file logging — flatten across every XIP. */
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
    const auto&       cfg         = emu_.Get<DeviceConfig>();
    const std::string device_dir  = GetCerfDir() + "devices/"
                                  + cfg.device_name + "/";

    std::vector<std::string> filenames;
    if (cfg.boot_in_recovery) {
        /* --recovery: boot the standalone recovery ROM instead of the
           primary (+extensions). Recovery is self-contained. */
        if (cfg.rom_recovery.empty()) {
            LOG(Caution, "RomParser: --recovery requested but device '%s' "
                         "declares no rom.recovery\n", cfg.device_name.c_str());
            return;
        }
        LOG(Boot, "RomParser: RECOVERY MODE — booting %s\n",
            cfg.rom_recovery.c_str());
        filenames.push_back(cfg.rom_recovery);
    } else if (!cfg.rom_primary.empty()) {
        filenames.push_back(cfg.rom_primary);
        for (const auto& ext : cfg.rom_extensions) filenames.push_back(ext);
        if (!cfg.rom_recovery.empty()) {
            LOG(Boot, "RomParser: rom_recovery=%s declared, not loaded "
                      "(pass --recovery to boot it)\n",
                cfg.rom_recovery.c_str());
        }
    } else {
        const std::string fname = FindFirstRomFile(device_dir);
        if (fname.empty()) {
            LOG(Caution, "RomParser: no .nb0 / .bin in %s\n", device_dir.c_str());
            return;
        }
        filenames.push_back(fname);
    }

    loaded_.reserve(filenames.size());
    for (size_t i = 0; i < filenames.size(); ++i) {
        ParsedRom rom;
        rom.filename = filenames[i];
        rom.path     = device_dir + filenames[i];
        if (!ParseOne(rom)) {
            loaded_.clear();
            return;
        }
        loaded_.push_back(std::move(rom));
    }

    LOG(Boot, "RomParser: %zu partition(s) loaded (primary=%s%s)\n",
        loaded_.size(), loaded_[0].filename.c_str(),
        loaded_.size() > 1 ? ", +extensions" : "");
    ok_ = true;
}

const ParsedTOCentry* RomParserService::KernelModule() const {
    if (loaded_.empty()) return nullptr;
    for (const auto& xip : loaded_[0].xips) {
        for (const auto& m : xip.toc.modules) {
            if (EqualIgnoreCase(m.lpszFileName, "nk.exe")) return &m;
        }
    }
    return nullptr;
}

std::span<const uint8_t>
RomParserService::ReadVa(uint32_t va, uint32_t len) const {
    for (const auto& rom : loaded_) {
        for (const auto& xip : rom.xips) {
            if (va < xip.load_offset) continue;
            const size_t off = size_t(va - xip.load_offset);
            if (off + len <= rom.flat.size())
                return rom.flat.subspan(off, len);
        }
    }
    return {};
}

std::span<const uint8_t>
RomParserService::ModuleBytesByName(const char* name) const {
    for (const auto& rom : loaded_) {
        for (const auto& xip : rom.xips) {
            for (const auto& m : xip.toc.modules) {
                if (!EqualIgnoreCase(m.lpszFileName, name)) continue;
                if (m.ulE32Offset < xip.load_offset) return {};
                const size_t e32_off =
                    size_t(m.ulE32Offset - xip.load_offset);
                if (e32_off + 0x18 > rom.flat.size()) return {};
                const uint32_t vsize = U32(rom.flat.data(), e32_off + 0x14);
                return ReadVa(m.ulLoadOffset, vsize);
            }
        }
    }
    return {};
}
