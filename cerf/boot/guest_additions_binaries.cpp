#include "guest_additions_binaries.h"

#include "../core/byte_order.h"
#include "../core/cerf_emulator.h"
#include "../core/log.h"
#include "../core/string_utils.h"
#include "../cpu/arm_processor_config.h"
#include "../boards/board_context.h"
#include "../peripherals/cerf_virt/cerf_virt_addr_map.h"
#include "pe_image.h"
#include "rom_parser_service.h"

REGISTER_SERVICE(GuestAdditionsBinaries);

namespace {
constexpr const char* kBodyDll = "cerf_guest.dll";
constexpr const char* kStubDll = "cerf_guest_stub.dll";
}  /* namespace */

std::string GuestAdditionsBinaries::ArchDir() {
    if (emu_.Get<BoardContext>().GetCpuArch() == CpuArch::Mips) {
        const ParsedRom& rom = emu_.Get<RomParserService>().Primary();
        const uint16_t cpu = rom.xips.empty() ? 0 : rom.xips[0].toc.romhdr.usCPUType;
        return cpu == PeImage::kMachineMipsFpu ? "mips4" : "mips1";
    }
    return emu_.Get<ArmProcessorConfig>().HasThumb() ? "arm_thumb" : "arm";
}

std::string GuestAdditionsBinaries::BodyPath() {
    return GetCerfDir() + "ce_apps\\" + ArchDir() + "\\" + kBodyDll;
}

std::string GuestAdditionsBinaries::StubPath() {
    return GetCerfDir() + "ce_apps\\" + ArchDir() + "\\" + kStubDll;
}

void GuestAdditionsBinaries::StampWindowBase(std::vector<uint8_t>& image) {
    const uint32_t base  = emu_.Get<BoardContext>().GuestAdditionsWindowBase();
    const uint32_t magic = CerfVirt::kBaseMagic;

    size_t hits = 0, at = 0;
    for (size_t i = 0; i + 4u <= image.size(); ++i) {
        if (cerf::le::U32(image.data(), i) == magic) {
            ++hits;
            at = i;
        }
    }
    if (hits != 1) {
        LOG(Caution, "GuestAdditions: base sentinel 0x%08X found %zu time(s) in the "
                "guest image (expected exactly 1) - magic collided or g_CerfVirtBase "
                "is absent\n", magic, hits);
        CerfFatalExit(CERF_FATAL_RUNTIME_ERROR);
    }
    cerf::le::Put32(image.data() + at, base);
    LOG(GuestAdditions, "base sentinel stamped -> 0x%08X at image offset 0x%zX\n",
        base, at);
}
