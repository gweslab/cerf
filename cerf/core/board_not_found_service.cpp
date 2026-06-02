#define NOMINMAX

#include "../boards/board_detector.h"
#include "../boot/rom_parser_service.h"
#include "cerf_emulator.h"
#include "log.h"
#include "service.h"

#include <windows.h>

namespace {

class BoardNotFoundService : public Service {
public:
    using Service::Service;

    bool ShouldRegister() override {
        /* "Unsupported board" only applies once a ROM actually loaded; a
           missing ROM is DeviceNotFoundService's job (launcher bootstrap),
           so defer when the parser found nothing to inspect. */
        return emu_.Get<RomParserService>().Ok()
            && emu_.Get<BoardDetector>().GetBoard() == Board::Unknown;
    }

    void OnReady() override {
        LOG(Caution, "no BoardDetector candidate matched this ROM -- CERF "
                     "does not support this board / device.\n");

#if !CERF_DEV_MODE
        MessageBoxA(nullptr,
                    "CERF doesn't support this board / device.\n\n"
                    "No BoardDetector matched the loaded ROM. CERF will exit.",
                    "CERF: unsupported board",
                    MB_OK | MB_ICONERROR);
#endif

        CerfFatalExit(CERF_FATAL_USER_ERROR);
    }
};

}  /* namespace */

REGISTER_SERVICE(BoardNotFoundService);
