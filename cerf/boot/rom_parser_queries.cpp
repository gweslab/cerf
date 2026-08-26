#include "rom_parser_queries.h"

#include "rom_image_parse.h"

#include "../boards/board_context.h"
#include "../core/cerf_emulator.h"
#include "../core/log.h"

#include <cctype>
#include <cstring>

REGISTER_SERVICE(RomParserQueries);

namespace {

using cerf::rom_image_parse::U32;

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

}  /* namespace */

bool RomParserQueries::ShouldRegister() {
    return emu_.Get<BoardContext>().GetRomPlacingMode()
        == RomPlacingMode::FlatContainer;
}

void RomParserQueries::OnReady() {
    uint16_t major = 0, minor = 0;
    if (KernelSubsystemVersion(major, minor))
        LOG(Boot, "RomParser: kernel subsystem version %u.%u\n", major, minor);
}

const std::vector<ParsedRom>& RomParserQueries::Loaded() const {
    return emu_.Get<RomParserService>().Loaded();
}

const ParsedTOCentry* RomParserQueries::KernelModule() const {
    const auto& loaded = Loaded();
    if (loaded.empty()) return nullptr;
    for (const auto& xip : loaded[0].xips) {
        for (const auto& m : xip.toc.modules) {
            if (EqualIgnoreCase(m.lpszFileName, "nk.exe")) return &m;
        }
    }
    return nullptr;
}

std::span<const uint8_t>
RomParserQueries::ReadVa(uint32_t va, uint32_t len) const {
    for (const auto& rom : Loaded()) {
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
RomParserQueries::ModuleBytesByName(const char* name) const {
    for (const auto& rom : Loaded()) {
        if (rom.is_ce1) {
            LOG(Caution, "RomParser: ModuleBytesByName('%s') on a CE 1.0 image "
                         "is not implemented\n", name);
            CerfFatalExit(CERF_FATAL_RUNTIME_ERROR);
        }
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

bool RomParserQueries::KernelSubsystemVersion(uint16_t& major,
                                              uint16_t& minor) const {
    for (const auto& rom : Loaded()) {
        if (rom.is_ce1) return false;
        for (const auto& xip : rom.xips) {
            for (const auto& m : xip.toc.modules) {
                if (!EqualIgnoreCase(m.lpszFileName, "nk.exe")) continue;
                if (m.ulE32Offset < xip.load_offset) return false;
                const size_t e32_off = size_t(m.ulE32Offset - xip.load_offset);
                if (e32_off + 0x10 > rom.flat.size()) return false;
                const uint8_t* p = rom.flat.data() + e32_off;
                major = uint16_t(p[0x0C] | (p[0x0D] << 8));
                minor = uint16_t(p[0x0E] | (p[0x0F] << 8));
                return true;
            }
        }
    }
    return false;
}
