/*
 * CERF - Windows CE Runtime Foundation
 *
 * Loads Windows CE ARM executables and emulates them on x64 desktop Windows
 * by interpreting ARM instructions and thunking COREDLL.DLL API calls to
 * native Win32 APIs.
 *
 * Usage: cerf.exe <path-to-arm-wince-exe>
 */

#include <windows.h>
#include <cstdio>
#include <cstdlib>
#include <string>
#include <vector>
#include <algorithm>

#include "log.h"
#include "cpu/mem.h"
#include "cpu/arm_cpu.h"
#include "loader/pe_loader.h"
#include "thunks/win32_thunks.h"

static void PrintUsage(const char* prog) {
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

static void DumpRegisters(ArmCpu& cpu) {
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

int main(int argc, char* argv[]) {
    const char* exe_path = nullptr;
    const char* device_override = nullptr;
    bool trace = false;
    bool explicit_log = false;
    const char* log_file = nullptr;
    bool flush_outputs = false;
    uint32_t no_log_mask = 0;
    int cli_fake_screen_resolution = -1; /* -1=unset, 0=false, 1=true */
    int cli_screen_width = 0;
    int cli_screen_height = 0;
    int cli_os_major = -1, cli_os_minor = -1, cli_os_build = -1;
    const char* cli_os_build_date = nullptr;
    int cli_fake_total_phys = 0;

    Log::Init();

    for (int i = 1; i < argc; i++) {
        if (strcmp(argv[i], "--trace") == 0) {
            trace = true;
            Log::EnableCategory(Log::TRACE);
        } else if (strncmp(argv[i], "--log=", 6) == 0) {
            Log::SetEnabled(Log::ParseCategories(argv[i] + 6));
            explicit_log = true;
        } else if (strncmp(argv[i], "--no-log=", 9) == 0) {
            no_log_mask |= Log::ParseCategories(argv[i] + 9);
        } else if (strncmp(argv[i], "--log-file=", 11) == 0) {
            log_file = argv[i] + 11;
        } else if (strcmp(argv[i], "--flush-outputs") == 0) {
            flush_outputs = true;
        } else if (strncmp(argv[i], "--device=", 9) == 0) {
            device_override = argv[i] + 9;
        } else if (strncmp(argv[i], "--fake-screen-resolution=", 25) == 0) {
            const char* val = argv[i] + 25;
            cli_fake_screen_resolution = (strcmp(val, "false") != 0 && strcmp(val, "0") != 0 && strcmp(val, "no") != 0) ? 1 : 0;
        } else if (strncmp(argv[i], "--screen-width=", 15) == 0) {
            cli_screen_width = atoi(argv[i] + 15);
        } else if (strncmp(argv[i], "--screen-height=", 16) == 0) {
            cli_screen_height = atoi(argv[i] + 16);
        } else if (strncmp(argv[i], "--os-major=", 11) == 0) {
            cli_os_major = atoi(argv[i] + 11);
        } else if (strncmp(argv[i], "--os-minor=", 11) == 0) {
            cli_os_minor = atoi(argv[i] + 11);
        } else if (strncmp(argv[i], "--os-build=", 11) == 0) {
            cli_os_build = atoi(argv[i] + 11);
        } else if (strncmp(argv[i], "--os-build-date=", 16) == 0) {
            cli_os_build_date = argv[i] + 16;
        } else if (strncmp(argv[i], "--fake-total-phys=", 18) == 0) {
            cli_fake_total_phys = atoi(argv[i] + 18);
        } else if (strcmp(argv[i], "--quiet") == 0) {
            Log::SetEnabled(Log::NONE);
            explicit_log = true;
        } else if (strcmp(argv[i], "--help") == 0 || strcmp(argv[i], "-h") == 0) {
            PrintUsage(argv[0]);
            return 0;
        } else if (!exe_path) {
            exe_path = argv[i];
        }
        /* Arguments after exe_path are for the ARM app (visible via GetCommandLineW) */
    }

    /* Apply --no-log after everything else */
    if (no_log_mask) {
        Log::SetEnabled(Log::GetEnabled() & ~no_log_mask);
    }

    if (flush_outputs) {
        Log::SetFlush(true);
    }

    if (log_file) {
        Log::SetFile(log_file);
    }

    if (!exe_path) {
        PrintUsage(argv[0]);
        return 1;
    }

    LOG_RAW("=== CERF - Windows CE Runtime Foundation ===\n");
    LOG_RAW("Loading: %s\n\n", exe_path);

    /* Initialize emulated memory */
    EmulatedMemory mem;

    /* Load the PE file */
    PEInfo pe_info = {};
    uint32_t entry_point = PELoader::Load(exe_path, mem, pe_info);
    if (entry_point == 0) {
        LOG_ERR("Failed to load PE file\n");
        return 1;
    }

    /* Verify it's ARM */
    if (pe_info.machine != 0x01C0 && pe_info.machine != 0x01C2) {
        LOG_ERR("Not an ARM executable (machine=0x%04X)\n", pe_info.machine);
        return 1;
    }

    LOG(EMU, "\n[EMU] ARM %s detected (machine=0x%04X)\n",
           pe_info.machine == 0x01C2 ? "Thumb" : "32-bit",
           pe_info.machine);

    /* Set up thunks */
    Win32Thunks thunks(mem);
    thunks.SetHInstance(pe_info.image_base);

    /* Convert exe path to wide string */
    std::wstring wide_path;
    for (const char* p = exe_path; *p; p++) wide_path += (wchar_t)*p;
    thunks.SetExePath(wide_path);

    /* Extract directory from exe path */
    std::string exe_dir;
    {
        std::string path_str(exe_path);
        size_t last_sep = path_str.find_last_of("\\/");
        if (last_sep != std::string::npos)
            exe_dir = path_str.substr(0, last_sep + 1);
    }
    thunks.SetExeDir(exe_dir);

    /* Initialize virtual filesystem — reads cerf.ini, sets up device paths.
       This also sets wince_sys_dir for ARM DLL loading. */
    thunks.InitVFS(device_override ? device_override : "");

    /* CLI overrides take priority over cerf.ini */
    if (cli_fake_screen_resolution >= 0)
        thunks.fake_screen_resolution = (cli_fake_screen_resolution != 0);
    if (cli_screen_width > 0)
        thunks.screen_width = (uint32_t)cli_screen_width;
    if (cli_screen_height > 0)
        thunks.screen_height = (uint32_t)cli_screen_height;
    if (cli_os_major >= 0) thunks.os_major = (uint32_t)cli_os_major;
    if (cli_os_minor >= 0) thunks.os_minor = (uint32_t)cli_os_minor;
    if (cli_os_build >= 0) thunks.os_build = (uint32_t)cli_os_build;
    if (cli_os_build_date) thunks.os_build_date = cli_os_build_date;
    if (cli_fake_total_phys > 0) thunks.fake_total_phys = (uint32_t)cli_fake_total_phys;

    /* Install import thunks */
    thunks.InstallThunks(pe_info);

    /* Allocate stack */
    uint32_t stack_top = mem.AllocStack();

    /* Initialize CPU */
    ArmCpu cpu;
    cpu.mem = &mem;
    cpu.trace = trace;

    /* Set up initial register state */
    cpu.r[REG_SP] = stack_top;
    cpu.r[REG_LR] = 0xDEADDEAD; /* Sentinel return address */
    cpu.r[REG_PC] = entry_point;

    /* Set up entry point arguments (WinMain style):
       R0 = hInstance
       R1 = hPrevInstance (always NULL)
       R2 = lpCmdLine (empty string)
       R3 = nCmdShow (SW_SHOW = 5) */
    cpu.r[0] = pe_info.image_base;  /* hInstance */
    cpu.r[1] = 0;                    /* hPrevInstance */

    /* Build lpCmdLine from arguments after exe_path */
    uint32_t cmdline_addr = 0x60000000;
    mem.Alloc(cmdline_addr, 0x1000);
    {
        std::wstring cmdline_str;
        bool found_exe = false;
        for (int i = 1; i < argc; i++) {
            if (!found_exe && argv[i] == exe_path) {
                found_exe = true;
                continue;
            }
            if (!found_exe) continue; /* skip options before exe_path */
            if (!cmdline_str.empty()) cmdline_str += L' ';
            for (const char* p = argv[i]; *p; p++)
                cmdline_str += (wchar_t)*p;
        }
        /* Write wide string to emulated memory */
        for (size_t j = 0; j < cmdline_str.size() && j < 0x7FE; j++)
            mem.Write16(cmdline_addr + (uint32_t)(j * 2), (uint16_t)cmdline_str[j]);
        mem.Write16(cmdline_addr + (uint32_t)(cmdline_str.size() * 2), 0);
    }
    cpu.r[2] = cmdline_addr;
    cpu.r[3] = 1; /* SW_SHOWNORMAL */

    /* Determine initial mode (ARM or Thumb) based on entry point bit 0.
       Machine type 0x01C2 (IMAGE_FILE_MACHINE_THUMB) means the binary supports
       Thumb instructions, but the entry point itself may be ARM or Thumb —
       bit 0 of the address determines the mode (standard ARM interworking). */
    if (entry_point & 1) {
        cpu.cpsr |= PSR_T;
        cpu.r[REG_PC] = entry_point & ~1u;
    }

    /* Set up thunk handler */
    cpu.thunk_handler = [&thunks](uint32_t addr, uint32_t* regs, EmulatedMemory& mem_ref) -> bool {
        /* Check for sentinel return address (program exit) */
        if (addr == 0xDEADDEAD) {
            LOG(EMU, "\n[EMU] Program returned from entry point with code %d\n", regs[0]);
            ExitProcess(regs[0]);
            return true;
        }
        /* Callback sentinel - set PC so the callback executor loop detects it */
        if (addr == 0xCAFEC000) {
            regs[15] = 0xCAFEC000;
            return true;
        }
        return thunks.HandleThunk(addr, regs, mem_ref);
    };

    /* Set up callback executor for calling ARM code from native callbacks
       (e.g., WndProc, timer callbacks, dialog procs) */
    uint32_t cb_sentinel = 0xCAFEC000; /* Must be 4-byte aligned for LDM/POP PC */
    mem.Alloc(cb_sentinel, 0x1000);
    /* Write a BX LR instruction at the sentinel address as a safety net */
    mem.Write32(cb_sentinel, 0xE12FFF1E); /* BX LR */

    thunks.callback_executor = [&cpu, &mem, &thunks, cb_sentinel](
            uint32_t arm_addr, uint32_t* args, int nargs) -> uint32_t {
        static int cb_depth = 0;
        cb_depth++;
        if (cb_depth > 1) {
            LOG(API, "[API] callback_executor NESTED depth=%d addr=0x%08X args=[0x%X,0x%X,0x%X,0x%X]\n",
                cb_depth, arm_addr,
                nargs > 0 ? args[0] : 0, nargs > 1 ? args[1] : 0,
                nargs > 2 ? args[2] : 0, nargs > 3 ? args[3] : 0);
        }
        /* Save CPU state */
        uint32_t saved_regs[16];
        memcpy(saved_regs, cpu.r, sizeof(saved_regs));
        uint32_t saved_cpsr = cpu.cpsr;
        bool saved_halted = cpu.halted;
        cpu.halted = false;

        /* Set up callback arguments (R0-R3) */
        for (int i = 0; i < nargs && i < 4; i++) {
            cpu.r[i] = args[i];
        }

        /* Set LR to sentinel so we know when the callback returns */
        cpu.r[REG_LR] = cb_sentinel;

        /* Set PC to ARM function address */
        if (arm_addr & 1) {
            cpu.cpsr |= PSR_T;
            cpu.r[REG_PC] = arm_addr & ~1u;
        } else {
            cpu.cpsr &= ~PSR_T;
            cpu.r[REG_PC] = arm_addr;
        }

        /* Allocate a small stack frame for the callback and push extra args.
           ARM calling convention: args[0-3] in r0-r3, args[4+] on the stack.
           Stack grows downward; 5th arg at [SP+0], 6th at [SP+4], etc. */
        cpu.r[REG_SP] -= 0x100;
        for (int i = 4; i < nargs; i++) {
            mem.Write32(cpu.r[REG_SP] + (uint32_t)(i - 4) * 4, args[i]);
        }

        /* Run until callback returns (hits sentinel) */
        while (!cpu.halted) {
            uint32_t pc = cpu.r[REG_PC];
            if (pc == cb_sentinel || pc == (cb_sentinel & ~1u)) {
                break;
            }
            /* Detect null function pointer call — PC at 0 means the ARM code
               called through a NULL pointer.  Don't execute zeroed memory. */
            if (pc < 0x1000 && cb_depth > 1) {
                LOG(API, "[API] callback_executor: NULL function pointer (PC=0x%08X) at depth=%d, aborting\n",
                    pc, cb_depth);
                cpu.r[0] = 0;
                break;
            }
            cpu.Step();
        }

        if (cpu.halted && cb_depth > 1) {
            LOG(API, "[API] callback_executor HALTED at depth=%d PC=0x%08X R0=0x%X LR=0x%X\n",
                cb_depth, cpu.r[REG_PC], cpu.r[0], cpu.r[REG_LR]);
        }

        uint32_t result = cpu.r[0];

        /* Restore CPU state */
        memcpy(cpu.r, saved_regs, sizeof(saved_regs));
        cpu.cpsr = saved_cpsr;
        cpu.halted = saved_halted;

        if (cb_depth > 1) {
            LOG(API, "[API] callback_executor RETURN depth=%d result=0x%X\n", cb_depth, result);
        }
        cb_depth--;
        return result;
    };

    /* Call DllMain for any loaded ARM DLLs (must happen after callback_executor is set up) */
    thunks.CallDllEntryPoints();

    LOG(EMU, "\n[EMU] Starting execution at 0x%08X (%s mode)\n",
           cpu.r[REG_PC], cpu.IsThumb() ? "Thumb" : "ARM");
    LOG(EMU, "[EMU] Stack at 0x%08X, hInstance=0x%08X\n\n", cpu.r[REG_SP], cpu.r[0]);

    /* Run the emulator */
    cpu.Run();

    /* If we get here, CPU halted */
    LOG(EMU, "\n[EMU] CPU halted (code=%d) after %llu instructions\n", cpu.halt_code, cpu.insn_count);
    DumpRegisters(cpu);

    Log::Close();
    return cpu.halt_code;
}
