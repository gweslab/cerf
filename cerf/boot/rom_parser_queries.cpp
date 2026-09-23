#include "rom_parser_queries.h"

#include "rom_record_layout.h"

#include "../boards/board_context.h"
#include "../core/byte_order.h"
#include "../core/cerf_emulator.h"
#include "../core/log.h"

#include <cctype>
#include <cstring>

REGISTER_SERVICE(RomParserQueries);

namespace {

using cerf::le::U16;

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

bool RomParserQueries::KernelSubsystemVersion(uint16_t& major,
                                              uint16_t& minor) const {
    for (const auto& rom : Loaded()) {
        if (rom.is_ce1) return false;
        for (const auto& xip : rom.xips) {
            for (const auto& m : xip.toc.modules) {
                if (!EqualIgnoreCase(m.lpszFileName, "nk.exe")) continue;
                if (m.ulE32Offset < xip.load_offset) return false;
                const size_t e32_off = size_t(m.ulE32Offset - xip.load_offset);
                if (e32_off + kE32OffSubsysMinor + 2 > rom.flat.size()) return false;
                const uint8_t* p = rom.flat.data() + e32_off;
                major = U16(p, kE32OffSubsysMajor);
                minor = U16(p, kE32OffSubsysMinor);
                return true;
            }
        }
    }
    return false;
}
