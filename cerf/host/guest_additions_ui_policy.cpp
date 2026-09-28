#include "guest_additions_ui_policy.h"

#include "../boot/rom_parser_queries.h"
#include "../core/cerf_emulator.h"

REGISTER_SERVICE(GuestAdditionsUiPolicy);

bool GuestAdditionsUiPolicy::CeVersion(uint16_t& major, uint16_t& minor) const {
    auto* rom = emu_.TryGet<RomParserQueries>();
    return rom && rom->KernelSubsystemVersion(major, minor);
}

bool GuestAdditionsUiPolicy::LiveResizeAvailable() const {
    uint16_t maj = 0, min = 0;
    if (!CeVersion(maj, min)) return true;
    return maj > 3;
}
