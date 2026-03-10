#include "cli_helpers.h"
#include "log.h"
#include "cpu/arm_cpu.h"
#include <cstdio>

void PrintUsage(const char* prog) {
    printf("CERF - Windows CE Runtime Foundation\n");
    printf("Emulates Windows CE ARM executables on x86 desktop Windows.\n\n");
    printf("Usage: %s [options] <arm-wince-exe>\n\n", prog);
    printf("Options:\n");
    printf("  --trace                  Enable instruction tracing\n");
    printf("  --log=CATEGORIES         Enable only listed categories (comma-separated)\n");
    printf("                           Categories: THUNK,PE,EMU,TRACE,CPU,REG,DBG,ALL,NONE\n");
    printf("  --no-log=CATEGORIES      Disable specific categories\n");
    printf("  --log-file=PATH          Write logs to file (in addition to console)\n");
    printf("  --device=NAME            Device profile to use (default: from cerf.ini)\n");
    printf("  --screen-width=N         Screen width in pixels (default: 800)\n");
    printf("  --screen-height=N        Screen height in pixels (default: 480)\n");
    printf("  --fake-screen-resolution=BOOL  Override fake screen resolution (true/false)\n");
    printf("  --os-major=N             WinCE major version (default: 5)\n");
    printf("  --os-minor=N             WinCE minor version (default: 0)\n");
    printf("  --os-build=N             WinCE build number (default: 1)\n");
    printf("  --os-build-date=STR      WinCE build date (default: \"Jan  1 2008\")\n");
    printf("  --fake-total-phys=N      Fake total physical RAM in bytes (0 = real)\n");
    printf("  --flush-outputs          Flush after every log write (for complete captures)\n");
    printf("  --quiet                  Disable all log output\n");
    printf("  --help                   Show this help\n");
}

void DumpRegisters(ArmCpu& cpu) {
    LOG_RAW("\n--- CPU State ---\n");
    for (int i = 0; i < 16; i++) {
        const char* names[] = {
            "R0", "R1", "R2", "R3", "R4", "R5", "R6", "R7",
            "R8", "R9", "R10", "R11", "R12", "SP", "LR", "PC"
        };
        LOG_RAW("  %-3s = 0x%08X", names[i], cpu.r[i]);
        if ((i & 3) == 3) LOG_RAW("\n");
    }
    LOG_RAW("  CPSR = 0x%08X [%c%c%c%c %s]\n",
           cpu.cpsr,
           cpu.GetN() ? 'N' : '-',
           cpu.GetZ() ? 'Z' : '-',
           cpu.GetC() ? 'C' : '-',
           cpu.GetV() ? 'V' : '-',
           cpu.IsThumb() ? "Thumb" : "ARM");
    LOG_RAW("  Instructions executed: %llu\n", cpu.insn_count);
    LOG_RAW("-----------------\n\n");
}
