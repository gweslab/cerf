#define NOMINMAX
#include "pcmcia_auto_insert.h"

#include "../../boot/rom_parser_queries.h"
#include "../../core/cerf_emulator.h"
#include "../../core/cerf_paths.h"
#include "../../core/device_config.h"
#include "../../core/log.h"
#include "../../core/string_utils.h"
#include "../compactflash/compactflash_card.h"
#include "pcmcia_card_catalog.h"
#include "pcmcia_slot.h"

#include <cstdint>
#include <memory>
#include <string>

#include <windows.h>

REGISTER_SERVICE(PcmciaAutoInsert);

void PcmciaAutoInsert::InsertDefaultNetworkCard(PcmciaSlot& slot) {
    auto* rom = emu_.TryGet<RomParserQueries>();
    uint16_t major = 0, minor = 0;
    if (!rom || !rom->KernelSubsystemVersion(major, minor)) {
        LOG(Net, "PcmciaAutoInsert: guest kernel version unavailable; "
                 "leaving '%ls' empty\n", slot.WidgetName().c_str());
        return;
    }
    if (major < 4) {
        LOG(Net, "PcmciaAutoInsert: guest kernel is CE %u.%u; leaving "
                 "'%ls' empty\n", major, minor, slot.WidgetName().c_str());
        return;
    }

    slot.InsertCard(emu_.Get<PcmciaCardCatalog>().Create("ne2000"));
}

void PcmciaAutoInsert::InsertLaunchCompactFlash(PcmciaSlot& slot) {
    const auto& cfg = emu_.Get<DeviceConfig>();
    for (const auto& card : cfg.bundled_compact_flash_cards) {
        if (!card.insert_on_launch) continue;

        const std::wstring path = Utf8ToWide(
            (GetDeviceDir(cfg.device_name) + card.file).c_str());

        if (GetFileAttributesW(path.c_str()) == INVALID_FILE_ATTRIBUTES) {
            const std::wstring name = Utf8ToWide(card.name.c_str());
            const std::wstring msg =
                L"This ROM requires additional package '" + name +
                L"' CF card to be present in the device directory. You can do "
                L"that in the launcher, in the right sidepanel.\n\n"
                L"The guest might not boot as intended without this card attached.";
            LOG(Caution, "PcmciaAutoInsert: launch CF '%ls' missing at '%ls'\n",
                name.c_str(), path.c_str());
            MessageBoxW(nullptr, msg.c_str(), L"Missing CF Card - CE Runtime Foundation",
                        MB_OK | MB_ICONWARNING);
            return;
        }

        slot.InsertCard(std::make_unique<CompactFlashCard>(emu_, path));
        LOG(Periph, "PcmciaAutoInsert: inserted launch CF '%s' into '%ls'\n",
            card.name.c_str(), slot.WidgetName().c_str());
        return;
    }
}
