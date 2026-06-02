#include "log.h"
#include "main_config.h"
#include "cerf_emulator.h"

#define WIN32_LEAN_AND_MEAN
#define NOMINMAX
#include <windows.h>
#include <timeapi.h>

int main(int argc, char* argv[]) {
    CerfConfig cfg;
    if (!ParseCerfArgs(argc, argv, cfg))
        return 0;

    /* Without this, sub-ms cv_.wait_for/Sleep round to the 15.625 ms
       Windows default quantum — OST IRQ latency breaks audio + UI. */
    timeBeginPeriod(1);

    Log::InitDefaultLogFile();

    LOG(Cerf, "=== CERF ===\n");
    LOG(Cerf, "Built: %s %s\n\n", __DATE__, __TIME__);

    CerfEmulator emu(cfg, argc, argv);
    emu.Boot();
    emu.WaitForExit();

    Log::Close();
    timeEndPeriod(1);
    return 0;
}
