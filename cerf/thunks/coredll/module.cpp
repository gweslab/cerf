#define NOMINMAX
#define _CRT_SECURE_NO_WARNINGS
/* Module/process management thunks */
#include "../win32_thunks.h"
#include "../../log.h"
#include "../../loader/pe_loader.h"
#include <algorithm>
#include <cstdio>

void Win32Thunks::RegisterModuleHandlers() {
    Thunk("GetModuleHandleW", 1177, [this](uint32_t* regs, EmulatedMemory& mem) -> bool {
        uint32_t name_addr = regs[0];
        if (name_addr == 0) {
            regs[0] = emu_hinstance;
            LOG(API, "[API] GetModuleHandleW(NULL) -> 0x%08X\n", regs[0]);
        } else {
            std::wstring name = ReadWStringFromEmu(mem, name_addr);
            LOG(API, "[API] GetModuleHandleW('%ls')\n", name.c_str());
            std::wstring lower = name;
            std::transform(lower.begin(), lower.end(), lower.begin(), ::towlower);
            auto* info = FindThunkedDllW(lower);
            regs[0] = info ? info->fake_handle : emu_hinstance;
        }
        return true;
    });
    Thunk("GetModuleFileNameW", 537, [this](uint32_t* regs, EmulatedMemory& mem) -> bool {
        uint32_t buf_addr = regs[1], buf_size = regs[2];
        /* Resolve the exe host path to absolute, then reverse-map to WinCE path.
           This gives the app its real installation directory. */
        wchar_t abs_buf[MAX_PATH] = {};
        if (GetFullPathNameW(exe_path.c_str(), MAX_PATH, abs_buf, NULL))
            { /* got absolute path */ }
        std::wstring wce_path = MapHostToWinCE(abs_buf[0] ? abs_buf : exe_path);
        LOG(API, "[API] GetModuleFileNameW() -> '%ls'\n", wce_path.c_str());
        for (uint32_t i = 0; i < wce_path.size() && i < buf_size; i++)
            mem.Write16(buf_addr + i * 2, wce_path[i]);
        uint32_t null_off = std::min((uint32_t)wce_path.size(), buf_size - 1);
        mem.Write16(buf_addr + null_off * 2, 0);
        regs[0] = (uint32_t)wce_path.size();
        return true;
    });
    Thunk("LoadLibraryW", 528, [this](uint32_t* regs, EmulatedMemory& mem) -> bool {
        std::wstring name = ReadWStringFromEmu(mem, regs[0]);
        LOG(API, "[API] LoadLibraryW('%ls')\n", name.c_str());
        std::wstring lower = name;
        std::transform(lower.begin(), lower.end(), lower.begin(), ::towlower);
        auto* info = FindThunkedDllW(lower);
        if (info) { regs[0] = info->fake_handle; LOG(API, "[API]   -> thunked (%s)\n", info->name); return true; }
        /* Use LoadArmDll which handles search paths, caching, and recursive import resolution */
        std::string narrow_name;
        for (auto c : name) narrow_name += (char)c;
        LoadedDll* dll = LoadArmDll(narrow_name);
        if (!dll) {
            LOG(API, "[API]   DLL not found: %s\n", narrow_name.c_str());
            regs[0] = 0; return true;
        }
        /* Call DllMain(DLL_PROCESS_ATTACH) if loaded fresh and callback_executor available */
        /* Note: LoadArmDll queues entry points, but for runtime loads we call immediately */
        if (callback_executor) {
            /* Check if there are pending inits for this DLL and call them now */
            for (auto it2 = pending_dll_inits.begin(); it2 != pending_dll_inits.end(); ) {
                if (it2->base_addr == dll->base_addr) {
                    LOG(API, "[API]   Calling DllMain at 0x%08X\n", it2->entry_point);
                    uint32_t args[3] = { it2->base_addr, 1 /* DLL_PROCESS_ATTACH */, 0 };
                    uint32_t result = callback_executor(it2->entry_point, args, 3);
                    LOG(API, "[API]   DllMain returned %d\n", result);
                    it2 = pending_dll_inits.erase(it2);
                } else {
                    ++it2;
                }
            }
        }
        regs[0] = dll->base_addr;
        return true;
    });
    /* Shared logic for GetProcAddress variants. is_wide=true for GetProcAddressW
       (WinCE-specific: takes wide string for function name) */
    auto getProcAddrImpl = [this](uint32_t* regs, EmulatedMemory& mem, bool is_wide) -> bool {
        uint32_t hmod = regs[0];
        /* Resolve hmod to the correct DLL name via the thunked DLL table */
        std::string dll_name = "coredll.dll";
        bool is_thunked_dll = false;
        for (const auto& dll : thunked_dlls) {
            if (hmod == dll.fake_handle) {
                dll_name = std::string(dll.name) + ".dll";
                is_thunked_dll = true;
                break;
            }
        }
        /* Check if hmod is a loaded ARM DLL (not a thunked system DLL) */
        const LoadedDll* arm_dll = nullptr;
        if (!is_thunked_dll) {
            for (const auto& [name, dll] : loaded_dlls) {
                if (dll.base_addr == hmod) {
                    arm_dll = &dll;
                    break;
                }
            }
        }
        /* Read function name or ordinal */
        std::string func_name;
        uint16_t ordinal = 0;
        bool by_ordinal = false;
        if ((regs[1] & 0xFFFF0000) == 0 && regs[1] != 0) {
            ordinal = (uint16_t)regs[1];
            by_ordinal = true;
            func_name = ResolveOrdinal(ordinal, dll_name);
        } else {
            if (is_wide) {
                std::wstring wname = ReadWStringFromEmu(mem, regs[1]);
                for (auto c : wname) func_name += (char)c;
            } else {
                func_name = ReadStringFromEmu(mem, regs[1]);
            }
        }
        /* For loaded ARM DLLs, resolve export from the PE export table */
        if (arm_dll) {
            LOG(API, "[API] GetProcAddress%s(0x%08X [ARM DLL], '%s')\n",
                   is_wide ? "W" : "", hmod, func_name.c_str());
            uint32_t addr = 0;
            if (by_ordinal) {
                addr = PELoader::ResolveExportOrdinal(mem, arm_dll->pe_info, ordinal);
            } else {
                addr = PELoader::ResolveExportName(mem, arm_dll->pe_info, func_name);
            }
            if (addr) {
                LOG(API, "[API]   -> ARM export at 0x%08X\n", addr);
            } else {
                LOG(API, "[API]   -> export not found\n");
            }
            regs[0] = addr;
            return true;
        }
        if (by_ordinal) {
            LOG(API, "[API] GetProcAddress(0x%08X [%s], ordinal %d -> %s)\n", hmod, dll_name.c_str(), ordinal,
                   func_name.empty() ? "UNKNOWN" : func_name.c_str());
            regs[0] = AllocThunk(dll_name, func_name, ordinal, func_name.empty());
            return true;
        }
        LOG(API, "[API] GetProcAddress%s(0x%08X [%s], '%s')\n",
               is_wide ? "W" : "", hmod, dll_name.c_str(), func_name.c_str());
        if (FindThunkedDll(dll_name) != nullptr || func_name.size() > 0) {
            regs[0] = AllocThunk(dll_name, func_name, 0, false);
            LOG(API, "[API]   -> thunk at 0x%08X\n", regs[0]);
        } else {
            regs[0] = 0;
        }
        return true;
    };
    Thunk("GetProcAddressW", 530, [getProcAddrImpl](uint32_t* regs, EmulatedMemory& mem) -> bool {
        return getProcAddrImpl(regs, mem, true);
    });
    Thunk("GetProcAddressA", [getProcAddrImpl](uint32_t* regs, EmulatedMemory& mem) -> bool {
        return getProcAddrImpl(regs, mem, false);
    });
    Thunk("GetProcAddress", [getProcAddrImpl](uint32_t* regs, EmulatedMemory& mem) -> bool {
        return getProcAddrImpl(regs, mem, false);
    });
    Thunk("GetCommandLineW", 1231, [this](uint32_t* regs, EmulatedMemory& mem) -> bool {
        static uint32_t cmdline_addr = 0;
        if (cmdline_addr == 0) {
            cmdline_addr = 0x50000000;
            mem.Alloc(cmdline_addr, 0x1000);
            LPCWSTR cmdline = GetCommandLineW();
            for (int i = 0; cmdline[i]; i++)
                mem.Write16(cmdline_addr + i * 2, cmdline[i]);
        }
        regs[0] = cmdline_addr;
        return true;
    });
    Thunk("CacheSync", 577, [](uint32_t* regs, EmulatedMemory&) -> bool { regs[0] = 1; return true; });
    Thunk("CacheRangeFlush", 1765, [](uint32_t* regs, EmulatedMemory&) -> bool { regs[0] = 1; return true; });
    Thunk("ExitProcess", [](uint32_t* regs, EmulatedMemory&) -> bool {
        LOG(API, "[API] ExitProcess(%d)\n", regs[0]); ExitProcess(regs[0]); return true;
    });
    Thunk("TerminateProcess", 544, [](uint32_t* regs, EmulatedMemory&) -> bool {
        LOG(API, "[API] ExitProcess(%d)\n", regs[0]); ExitProcess(regs[0]); return true;
    });
    Thunk("ExitThread", 6, [](uint32_t* regs, EmulatedMemory&) -> bool {
        LOG(API, "[API] ExitThread(%d)\n", regs[0]); ExitThread(regs[0]); return true;
    });
    Thunk("FreeLibrary", 529, [this](uint32_t* regs, EmulatedMemory& mem) -> bool {
        LOG(API, "[API] FreeLibrary(hModule=0x%08X) -> TRUE (stub)\n", regs[0]);
        regs[0] = 1; /* TRUE */
        return true;
    });
    Thunk("DisableThreadLibraryCalls", 1232, [](uint32_t* regs, EmulatedMemory&) -> bool {
        LOG(API, "[API] DisableThreadLibraryCalls(hModule=0x%08X) -> TRUE\n", regs[0]);
        regs[0] = 1;
        return true;
    });
    Thunk("LoadLibraryExW", 1241, [this](uint32_t* regs, EmulatedMemory& mem) -> bool {
        std::wstring name = ReadWStringFromEmu(mem, regs[0]);
        uint32_t flags = regs[2];
        LOG(API, "[API] LoadLibraryExW('%ls', flags=0x%X)\n", name.c_str(), flags);
        std::wstring lower = name;
        std::transform(lower.begin(), lower.end(), lower.begin(), ::towlower);
        auto* info = FindThunkedDllW(lower);
        if (info) { regs[0] = info->fake_handle; return true; }
        std::string narrow_name;
        for (auto c : name) narrow_name += (char)c;
        LoadedDll* dll = LoadArmDll(narrow_name);
        if (!dll) {
            LOG(API, "[API]   DLL not found: %s\n", narrow_name.c_str());
            regs[0] = 0; return true;
        }
        /* LOAD_LIBRARY_AS_DATAFILE (0x2) — skip DllMain, just return handle for resources */
        bool as_datafile = (flags & 0x2) != 0;
        if (!as_datafile && callback_executor) {
            for (auto it2 = pending_dll_inits.begin(); it2 != pending_dll_inits.end(); ) {
                if (it2->base_addr == dll->base_addr) {
                    LOG(API, "[API]   Calling DllMain at 0x%08X\n", it2->entry_point);
                    uint32_t args[3] = { it2->base_addr, 1, 0 };
                    callback_executor(it2->entry_point, args, 3);
                    it2 = pending_dll_inits.erase(it2);
                } else {
                    ++it2;
                }
            }
        }
        regs[0] = dll->base_addr;
        return true;
    });
    Thunk("GetExitCodeThread", 518, [](uint32_t* regs, EmulatedMemory& mem) -> bool {
        LOG(API, "[API] GetExitCodeThread(hThread=0x%08X, lpExitCode=0x%08X) -> stub\n", regs[0], regs[1]);
        if (regs[1]) mem.Write32(regs[1], 0);
        regs[0] = 1;
        return true;
    });
}
