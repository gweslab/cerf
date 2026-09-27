#include "cli_usage.h"

#include "board_database.h"
#include "cerf_emulator.h"
#include "log.h"

#include <cstdio>

REGISTER_SERVICE(CliUsage);

void CliUsage::Print(const char* prog) {
    printf("CE Runtime Foundation (CERF) - Universal Windows CE Emulator\n\n");
    printf("Usage: %s [options]\n\n", prog);
    printf("Options:\n");
    printf("  --device=NAME            Bundle to boot (default from cerf.json)\n");
    printf("  --board-id=ID            Board to emulate (overrides cerf.json board.id; see list below)\n");
    printf("  --rom-primary=FILE       Boot this ROM container (overrides cerf.json rom.primary)\n");
    printf("  --log=CATEGORIES         Enable only listed log categories (comma-sep)\n");
    printf("  --no-log=CATEGORIES      Disable specific categories\n");
    printf("  --log-file=PATH          Write logs to PATH (default cerf.log next to exe)\n");
    printf("  --flush-outputs          Flush log file after every write\n");
    printf("  --timeout=SECONDS        Stop the run after SECONDS and exit with code %d\n", CERF_FATAL_TIMEOUT);
    printf("  --allow-flood            Disable stdout anti-flood\n");
    printf("  --quiet                  Disable all log output\n");
    printf("  --disable-network        Force-disable network backend\n");
    printf("  --screen-width=N         Override device cerf.json board.configurable_screen_width\n");
    printf("  --screen-height=N        Override device cerf.json board.configurable_screen_height\n");
    printf("  --screen-dpi=N           Force guest display DPI (logical px/inch; guest-additions only)\n");
    printf("  --screen-bpp=N           Force guest display colour depth in bits per pixel\n");
    printf("  --screen-refresh-rate=N  Force guest refresh rate in Hz (default: host monitor max)\n");
    printf("  --guest-additions        Inject CERF guest-additions DLL into the ROM\n");
    printf("                           (replaces matching modules with CERF-built equivalents)\n");
    printf("  --ga-color-scheme=KEY    Override the guest system colors (needs --guest-additions)\n");
    printf("  --ga-font-size=N         Override the guest system font height in logical units\n");
    printf("                           (needs --guest-additions)\n");
    printf("  --ga-autorun=PATH        Start PATH in the guest once its shell is up (repeatable;\n");
    printf("                           needs --guest-additions)\n");
    printf("  --ga-share-folder=PATH   Mount the host directory PATH into the guest at boot\n");
    printf("                           (relative to the cerf.exe directory; needs --guest-additions)\n");
    printf("  --recovery               Boot the device's recovery ROM (rom.recovery) instead of primary\n");
    printf("  --boot=resume|cold|warm  Saved-state boot action when state.img exists\n");
    printf("                           (resume=full restore, warm=RAM+flash only, cold=ignore)\n");
    printf("  --tab=boot|hw|fb         Startup tab: boot screen, hardware console, or framebuffer\n");
    printf("                           (default: hw in dev, boot in release)\n");
    printf("  --full-screen            Enter borderless fullscreen (host key + F) once the window is shown\n");
    printf("  --no-focus               Never take the foreground from another application; windows\n");
    printf("                           open at the bottom of the Z order until you switch to them\n");
    printf("  --help                   Show this help\n");
    printf("\n");
    printf("Board ids (cerf.json board.id / --board-id):\n  ");
    bool first = true;
    for (const auto& d : emu_.Get<BoardDatabase>().Devices()) {
        printf("%s%s", first ? "" : ", ", d.id.c_str());
        first = false;
    }
    printf("\n\n");
    Log::PrintCategoryList();
}
