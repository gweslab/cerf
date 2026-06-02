#define NOMINMAX

#include "board_detector.h"

#include "../boot/rom_parser_service.h"
#include "../core/cerf_emulator.h"
#include "../core/log.h"

#include <cstring>

void BoardDetector::OnReady() {
    LOG(Board, "detected board: %s (SoC %s)\n",
        BoardName(), SocFamilyName(GetSoc()));
}

const char* BoardDetector::SocFamilyName(SocFamily f) {
    switch (f) {
        case SocFamily::Unknown:   return "Unknown";
        case SocFamily::S3C2410:   return "S3C2410";
        case SocFamily::SA1110:    return "SA1110";
        case SocFamily::PXA25x:    return "PXA25x";
        case SocFamily::PXA27x:    return "PXA27x";
        case SocFamily::OMAP3530:  return "OMAP3530";
        case SocFamily::Poseidon:  return "Poseidon";
        case SocFamily::iMX31:     return "iMX31";
        case SocFamily::iMX32:     return "iMX32";
        case SocFamily::TegraAPX:  return "TegraAPX";
    }
    return "Unknown";
}

std::string BoardDetector::ModuleNames() const {
    std::string joined;
    for (const auto& rom : emu_.Get<RomParserService>().Loaded()) {
        for (const auto& xip : rom.xips) {
            for (const auto& m : xip.toc.modules) {
                joined += m.lpszFileName;
                joined += '\n';
            }
        }
    }
    return joined;
}

std::vector<uint8_t> BoardDetector::ReadKernelBlob() const {
    /* Scoping the fingerprint scan to the kernel module's own bytes
       (rather than the whole ROM) avoids false positives on short
       SoC names (e.g. "ODO", "OMAP35") that may appear in unrelated
       module content. */
    const auto bytes = emu_.Get<RomParserService>().ModuleBytesByName("nk.exe");
    return std::vector<uint8_t>(bytes.begin(), bytes.end());
}

bool BoardDetector::RomContainsString(const char* needle) const {
    for (const auto& rom : emu_.Get<RomParserService>().Loaded()) {
        if (ContainsString(rom.raw, needle)) return true;
    }
    return false;
}

bool BoardDetector::ContainsString(const std::vector<uint8_t>& bytes,
                                   const char* needle) {
    const size_t nlen = std::strlen(needle);
    if (nlen == 0 || bytes.size() < nlen) return false;

    /* ASCII match. */
    {
        const size_t end = bytes.size() - nlen;
        for (size_t i = 0; i <= end; ++i) {
            if (std::memcmp(bytes.data() + i, needle, nlen) == 0) return true;
        }
    }
    /* UTF-16 LE match: each ASCII byte becomes byte + 0x00. */
    {
        std::vector<uint8_t> wide(nlen * 2);
        for (size_t i = 0; i < nlen; ++i) {
            wide[i * 2]     = static_cast<uint8_t>(needle[i]);
            wide[i * 2 + 1] = 0;
        }
        if (bytes.size() < wide.size()) return false;
        const size_t end = bytes.size() - wide.size();
        for (size_t i = 0; i <= end; ++i) {
            if (std::memcmp(bytes.data() + i, wide.data(), wide.size()) == 0) return true;
        }
    }
    return false;
}

bool BoardDetector::NameContains(const std::string& names, const char* needle) {
    return names.find(needle) != std::string::npos;
}
