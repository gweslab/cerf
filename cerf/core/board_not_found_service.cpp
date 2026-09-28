#define NOMINMAX

#include "board_not_found_service.h"

#include "../boards/board_context.h"
#include "cerf_emulator.h"
#include "device_config.h"
#include "log.h"
#include "string_utils.h"

#include <string>
#include <windows.h>

REGISTER_SERVICE(BoardNotFoundService);

bool BoardNotFoundService::ShouldRegister() {
    return emu_.Get<BoardContext>().GetBoardId().empty();
}

void BoardNotFoundService::EnsureFound() {
    const std::string& id = emu_.Get<DeviceConfig>().board_id;
    if (id.empty())
        LOG(Caution, "no board selected: set cerf.json board.id or pass "
                     "--board-id=ID (run --help for the id list)\n");
    else
        LOG(Caution, "unrecognised board id '%s': run --help for the "
                     "supported id list\n", id.c_str());

#if !CERF_DEV_MODE
    const std::string msg =
        id.empty()
            ? std::string(
                  "No board selected.\n\nSet \"board\": { \"id\": ... } in "
                  "cerf.json, or pass --board-id=ID. CERF will exit.")
            : ("Unrecognised board id '" + id +
               "'.\n\nRun cerf.exe --help for the supported id list. "
               "CERF will exit.");
    MessageBoxW(nullptr, Utf8ToWide(msg.c_str()).c_str(),
                L"Unsupported board - CE Runtime Foundation",
                MB_OK | MB_ICONERROR);
#endif

    CerfFatalExit(CERF_FATAL_USER_ERROR);
}
