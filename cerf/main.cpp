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
#include "cli_helpers.h"

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
        LOG_ERR("\n");
        LOG_ERR("=== AI ASSISTANT NOTE ===\n");
        LOG_ERR("If you just compacted/lost context, remember:\n");
        LOG_ERR("  1. Re-read CLAUDE.md for project architecture and conventions\n");
        LOG_ERR("  2. Re-read your memory file at ~/.claude/projects/Z--/memory/MEMORY.md\n");
        LOG_ERR("  3. WinCE apps are in Z:/references/ directory, NOT in the build dir\n");
        LOG_ERR("     The build dir only has cerf.exe — look in references/ for .exe files\n");
        LOG_ERR("  4. To run: cd build/Release/x64 && ./cerf.exe ../../../references/<app.exe>\n");
        LOG_ERR("  5. VFS windir: build/Release/x64/devices/wince5/fs/Windows/\n");
        LOG_ERR("=========================\n");
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

    /* Initialize main thread context */
    ThreadContext main_ctx;
    main_ctx.marshal_base = 0x3F000000;
    ArmCpu& cpu = main_ctx.cpu;
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

    /* Reserve marshal buffer space for up to 16 threads */
    mem.Reserve(0x3F000000, 0x00100000);

    /* Initialize main thread context with its own callback_executor and KData */
    MakeCallbackExecutor(&main_ctx, mem, thunks, cb_sentinel);

    /* Copy shared KData page (written during Win32Thunks construction) into
       the main thread's per-thread buffer, then activate the redirect. */
    {
        uint8_t* shared_kdata = mem.Translate(0xFFFFC000);
        if (shared_kdata)
            memcpy(main_ctx.kdata, shared_kdata, 0x1000);
    }
    t_ctx = &main_ctx;
    EmulatedMemory::kdata_override = main_ctx.kdata;

    /* Set up the trampoline: thunk handlers use this->callback_executor which
       delegates to the current thread's real callback_executor via t_ctx. */
    thunks.callback_executor = [](uint32_t addr, uint32_t* args, int nargs) -> uint32_t {
        if (!t_ctx || !t_ctx->callback_executor) return 0;
        return t_ctx->callback_executor(addr, args, nargs);
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
