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

#include "mem.h"
#include "arm_cpu.h"
#include "pe_loader.h"
#include "win32_thunks.h"

static void PrintUsage(const char* prog) {
    printf("CERF - Windows CE Runtime Foundation\n");
    printf("Emulates Windows CE ARM executables on x86 desktop Windows.\n\n");
    printf("Usage: %s [options] <arm-wince-exe>\n\n", prog);
    printf("Options:\n");
    printf("  --trace    Enable instruction tracing\n");
    printf("  --help     Show this help\n");
}

static void DumpRegisters(ArmCpu& cpu) {
    printf("\n--- CPU State ---\n");
    for (int i = 0; i < 16; i++) {
        const char* names[] = {
            "R0", "R1", "R2", "R3", "R4", "R5", "R6", "R7",
            "R8", "R9", "R10", "R11", "R12", "SP", "LR", "PC"
        };
        printf("  %-3s = 0x%08X", names[i], cpu.r[i]);
        if ((i & 3) == 3) printf("\n");
    }
    printf("  CPSR = 0x%08X [%c%c%c%c %s]\n",
           cpu.cpsr,
           cpu.GetN() ? 'N' : '-',
           cpu.GetZ() ? 'Z' : '-',
           cpu.GetC() ? 'C' : '-',
           cpu.GetV() ? 'V' : '-',
           cpu.IsThumb() ? "Thumb" : "ARM");
    printf("  Instructions executed: %llu\n", cpu.insn_count);
    printf("-----------------\n\n");
}

int main(int argc, char* argv[]) {
    const char* exe_path = nullptr;
    bool trace = false;

    for (int i = 1; i < argc; i++) {
        if (strcmp(argv[i], "--trace") == 0) {
            trace = true;
        } else if (strcmp(argv[i], "--help") == 0 || strcmp(argv[i], "-h") == 0) {
            PrintUsage(argv[0]);
            return 0;
        } else {
            exe_path = argv[i];
        }
    }

    if (!exe_path) {
        PrintUsage(argv[0]);
        return 1;
    }

    printf("=== CERF - Windows CE Runtime Foundation ===\n");
    printf("Loading: %s\n\n", exe_path);

    /* Initialize emulated memory */
    EmulatedMemory mem;

    /* Load the PE file */
    PEInfo pe_info = {};
    uint32_t entry_point = PELoader::Load(exe_path, mem, pe_info);
    if (entry_point == 0) {
        fprintf(stderr, "Failed to load PE file\n");
        return 1;
    }

    /* Verify it's ARM */
    if (pe_info.machine != 0x01C0 && pe_info.machine != 0x01C2) {
        fprintf(stderr, "Not an ARM executable (machine=0x%04X)\n", pe_info.machine);
        return 1;
    }

    printf("\n[EMU] ARM %s detected (machine=0x%04X)\n",
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

    /* Allocate empty command line in emulated memory */
    uint32_t cmdline_addr = 0x60000000;
    mem.Alloc(cmdline_addr, 0x1000);
    mem.Write16(cmdline_addr, 0); /* Empty wide string */
    cpu.r[2] = cmdline_addr;
    cpu.r[3] = 1; /* SW_SHOWNORMAL */

    /* Determine initial mode (ARM or Thumb) */
    if (pe_info.machine == 0x01C2) {
        /* ARM Thumb executable */
        cpu.cpsr |= PSR_T;
    } else {
        /* Check if entry point has Thumb bit set */
        if (entry_point & 1) {
            cpu.cpsr |= PSR_T;
            cpu.r[REG_PC] = entry_point & ~1u;
        }
    }

    /* Set up thunk handler */
    cpu.thunk_handler = [&thunks](uint32_t addr, uint32_t* regs, EmulatedMemory& mem_ref) -> bool {
        /* Check for sentinel return address (program exit) */
        if (addr == 0xDEADDEAD) {
            printf("\n[EMU] Program returned from entry point with code %d\n", regs[0]);
            ExitProcess(regs[0]);
            return true;
        }
        /* Callback sentinel - handled in the callback executor loop */
        if (addr == 0xCAFEC000) {
            return true; /* Let the callback executor detect this via PC check */
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

        /* Allocate a small stack frame for the callback */
        cpu.r[REG_SP] -= 0x100;

        /* Run until callback returns (hits sentinel) */
        while (!cpu.halted) {
            uint32_t pc = cpu.r[REG_PC];
            if (pc == cb_sentinel || pc == (cb_sentinel & ~1u)) {
                break;
            }
            cpu.Step();
        }

        uint32_t result = cpu.r[0];

        /* Restore CPU state */
        memcpy(cpu.r, saved_regs, sizeof(saved_regs));
        cpu.cpsr = saved_cpsr;
        cpu.halted = saved_halted;

        return result;
    };

    printf("\n[EMU] Starting execution at 0x%08X (%s mode)\n",
           cpu.r[REG_PC], cpu.IsThumb() ? "Thumb" : "ARM");
    printf("[EMU] Stack at 0x%08X, hInstance=0x%08X\n\n", cpu.r[REG_SP], cpu.r[0]);

    /* Run the emulator */
    cpu.Run();

    /* If we get here, CPU halted */
    printf("\n[EMU] CPU halted (code=%d) after %llu instructions\n", cpu.halt_code, cpu.insn_count);
    DumpRegisters(cpu);

    return cpu.halt_code;
}
