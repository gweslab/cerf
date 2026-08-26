#include "nec_mobilepro_900_bootloader_seeder.h"

#include "../board_context.h"
#include "../../boot/guest_cold_boot.h"
#include "../../boot/rom_parser_queries.h"
#include "../../core/cerf_emulator.h"
#include "../../core/device_config.h"
#include "../../cpu/emulated_memory.h"

namespace {
constexpr uint32_t kDisplayMode640x240 = 2u;  /* 640x240 panel mode. */
}

void NecMobilePro900BootloaderSeeder::OnReady() {
    Write();
    emu_.Get<GuestColdBoot>().RegisterReplay([this] { Write(); });
}

void NecMobilePro900BootloaderSeeder::Write() {
    emu_.Get<EmulatedMemory>().WriteWord(DisplayModeSelectPa(),
                                         kDisplayMode640x240);
}

bool NecMobilePro900BootloaderSeeder::BoardMatchesKernelMajor(
        uint16_t major) const {
    auto* bd = emu_.TryGet<BoardContext>();
    if (!bd || bd->GetBoard() != Board::NecMobilePro900) return false;
    if (emu_.Get<DeviceConfig>().guest_additions) return false;
    uint16_t maj = 0, min = 0;
    return emu_.Get<RomParserQueries>().KernelSubsystemVersion(maj, min)
        && maj == major;
}
