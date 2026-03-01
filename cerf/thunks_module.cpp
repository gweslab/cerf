#define NOMINMAX
#define _CRT_SECURE_NO_WARNINGS
/* Module/process management thunks */
#include "win32_thunks.h"
#include "pe_loader.h"
#include <algorithm>
#include <cstdio>

void Win32Thunks::RegisterModuleHandlers() {
    Thunk("GetModuleHandleW", 1177, [this](uint32_t* regs, EmulatedMemory& mem) -> bool {
        uint32_t name_addr = regs[0];
        if (name_addr == 0) {
            regs[0] = emu_hinstance;
            printf("[THUNK] GetModuleHandleW(NULL) -> 0x%08X\n", regs[0]);
        } else {
            std::wstring name = ReadWStringFromEmu(mem, name_addr);
            printf("[THUNK] GetModuleHandleW('%ls')\n", name.c_str());
            std::wstring lower = name;
            std::transform(lower.begin(), lower.end(), lower.begin(), ::towlower);
            if (lower.find(L"coredll") != std::wstring::npos) {
                regs[0] = 0xCE000000;
            } else {
                regs[0] = emu_hinstance;
            }
        }
        return true;
    });
    Thunk("GetModuleFileNameW", 537, [this](uint32_t* regs, EmulatedMemory& mem) -> bool {
        uint32_t buf_addr = regs[1], buf_size = regs[2];
        for (uint32_t i = 0; i < exe_path.size() && i < buf_size; i++)
            mem.Write16(buf_addr + i * 2, exe_path[i]);
        uint32_t null_off = std::min((uint32_t)exe_path.size(), buf_size - 1);
        mem.Write16(buf_addr + null_off * 2, 0);
        regs[0] = (uint32_t)exe_path.size();
        return true;
    });
    Thunk("LoadLibraryW", 528, [this](uint32_t* regs, EmulatedMemory& mem) -> bool {
        std::wstring name = ReadWStringFromEmu(mem, regs[0]);
        printf("[THUNK] LoadLibraryW('%ls')\n", name.c_str());
        std::wstring lower = name;
        std::transform(lower.begin(), lower.end(), lower.begin(), ::towlower);
        if (lower.find(L"coredll") != std::wstring::npos) { regs[0] = 0xCE000000; return true; }
        auto it = loaded_dlls.find(lower);
        if (it != loaded_dlls.end()) {
            regs[0] = it->second.base_addr;
            printf("[THUNK]   Already loaded at 0x%08X\n", regs[0]);
            return true;
        }
        std::string narrow_name;
        for (auto c : name) narrow_name += (char)c;
        std::string dll_path = exe_dir + narrow_name;
        FILE* f = fopen(dll_path.c_str(), "rb");
        if (!f) { dll_path = narrow_name; f = fopen(dll_path.c_str(), "rb"); }
        if (!f) { printf("[THUNK]   DLL not found: %s\n", narrow_name.c_str()); regs[0] = 0; return true; }
        fclose(f);
        PEInfo dll_info = {};
        uint32_t entry = PELoader::LoadDll(dll_path.c_str(), mem, dll_info);
        if (entry == 0 && dll_info.image_base == 0) {
            printf("[THUNK]   Failed to load ARM DLL: %s\n", dll_path.c_str());
            regs[0] = 0; return true;
        }
        LoadedDll loaded;
        loaded.path = dll_path;
        loaded.base_addr = dll_info.image_base;
        loaded.pe_info = dll_info;
        loaded.native_rsrc_handle = NULL;
        loaded_dlls[lower] = loaded;
        regs[0] = dll_info.image_base;
        printf("[THUNK]   Loaded ARM DLL at 0x%08X\n", regs[0]);
        return true;
    });
    auto getProcAddr = [this](uint32_t* regs, EmulatedMemory& mem) -> bool {
        uint32_t hmod = regs[0];
        if ((regs[1] & 0xFFFF0000) == 0 && regs[1] != 0) {
            uint16_t ordinal = (uint16_t)regs[1];
            std::string resolved = ResolveOrdinal(ordinal);
            printf("[THUNK] GetProcAddress(0x%08X, ordinal %d -> %s)\n", hmod, ordinal,
                   resolved.empty() ? "UNKNOWN" : resolved.c_str());
            regs[0] = AllocThunk("coredll.dll", resolved, ordinal, resolved.empty());
            return true;
        }
        std::string func_name = ReadStringFromEmu(mem, regs[1]);
        printf("[THUNK] GetProcAddress(0x%08X, '%s')\n", hmod, func_name.c_str());
        if (hmod == 0xCE000000 || func_name.size() > 0) {
            regs[0] = AllocThunk("coredll.dll", func_name, 0, false);
            printf("[THUNK]   -> thunk at 0x%08X\n", regs[0]);
        } else {
            regs[0] = 0;
        }
        return true;
    };
    Thunk("GetProcAddressW", 530, getProcAddr);
    Thunk("GetProcAddressA", getProcAddr);
    Thunk("GetProcAddress", getProcAddr);
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
        printf("[THUNK] ExitProcess(%d)\n", regs[0]); ExitProcess(regs[0]); return true;
    });
    Thunk("TerminateProcess", 544, [](uint32_t* regs, EmulatedMemory&) -> bool {
        printf("[THUNK] ExitProcess(%d)\n", regs[0]); ExitProcess(regs[0]); return true;
    });
    Thunk("ExitThread", 6, [](uint32_t* regs, EmulatedMemory&) -> bool {
        printf("[THUNK] ExitThread(%d)\n", regs[0]); ExitThread(regs[0]); return true;
    });
}
